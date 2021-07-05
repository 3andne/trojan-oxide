use crate::{
    args::Opt,
    client::{http::*, socks5::*},
    server::trojan::*,
    tunnel::quic::*,
    utils::{
        copy_udp, new_trojan_udp_stream, ClientTcpStream, ConnectionRequest, MixAddrType,
        Socks5UdpStream,
    },
};
use anyhow::Result;
use futures::StreamExt;
use lazy_static::lazy_static;
use quinn::*;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::{net::SocketAddr, sync::atomic::Ordering};
use tokio::select;
use tokio::sync::{broadcast, oneshot};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
use tracing::*;

lazy_static! {
    static ref CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
    static ref QUIC_TUNNEL_RESET: AtomicBool = AtomicBool::new(false);
}

type ClientRequestAcceptResult = Result<(
    ConnectionRequest<ClientTcpStream, Socks5UdpStream>,
    MixAddrType,
)>;

macro_rules! request_accept_helper {
    ($fn_name:ident, $request_type:ident) => {
        async fn $fn_name(stream: TcpStream) -> ClientRequestAcceptResult {
            let mut req = $request_type::new();
            let conn_req = req.accept(stream).await?;
            Ok((conn_req, req.addr()))
        }
    };
}

request_accept_helper!(accept_http_request, HttpRequest);
request_accept_helper!(accept_sock5_request, Socks5Request);

async fn forward_through_quic<F, Fut>(
    stream: TcpStream,
    mut upper_shutdown: broadcast::Receiver<()>,
    tunnel: (SendStream, RecvStream),
    password_hash: Arc<String>,
    accept_client_request: F,
) -> Result<()>
where
    F: Fn(TcpStream) -> Fut + Send,
    Fut: Future<Output = ClientRequestAcceptResult> + Send,
{
    let x = accept_client_request(stream);
    let (conn_req, addr) = x.await?;
    let (mut out_write, mut out_read) = tunnel;
    let conn_id = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);

    use ConnectionRequest::*;
    match conn_req {
        TCP(mut stream) => {
            trojan_connect_tcp(&addr, &mut out_write, password_hash).await?;
            info!("[tcp][{}]{:?} => {:?}", conn_id, stream.peer_addr()?, &addr);
            let (mut in_read, mut in_write) = stream.split();
            select! {
                res = tokio::io::copy(&mut out_read, &mut in_write) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = tokio::io::copy(&mut in_read, &mut out_write) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
            debug!("[end][tcp][{}]", conn_id);
        }
        UDP(mut udp) => {
            trojan_connect_udp(&mut out_write, password_hash).await?;
            let (mut in_write, mut in_read) = udp.split();
            let (mut out_write, mut out_read) = new_trojan_udp_stream(out_write, out_read, None);
            info!("[udp] => {:?}", &addr);
            select! {
                res = copy_udp(&mut out_read, &mut in_write) => {
                    debug!("udp relaying upload end, {:?}", res);
                },
                res = copy_udp(&mut in_read, &mut out_write) => {
                    debug!("udp relaying download end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
        }
        ECHO(_) => panic!("unreachable"),
    }

    Ok(())
}

#[macro_export]
macro_rules! try_recv {
    ($T:tt, $instance:expr) => {
        try_recv!($T, $instance, break)
    };
    ($T:tt, $instance:expr, $then_expr:expr) => {
        match $instance.try_recv() {
            Err($T::error::TryRecvError::Empty) => (),
            _ => {
                tracing::info!("{} received", stringify!($instance));
                $then_expr;
            }
        }
    };
}

macro_rules! do_ {
    ($res:expr, $else_expr:expr) => {
        match $res {
            Ok(res) => res,
            Err(e) => {
                info!("{} failed due to {:?}", stringify!($res), e);
                $else_expr
            }
        }
    };
}

async fn user_endpoint_listener<F, Fut>(
    mut upper_shutdown: oneshot::Receiver<()>,
    service_addr: SocketAddr,
    options: Opt,
    accept_client_request: F,
) -> Result<()>
where
    F: Fn(TcpStream) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ClientRequestAcceptResult> + Send + 'static,
{
    let (shutdown_tx, _) = broadcast::channel(1);
    let service_listener = TcpListener::bind(&service_addr).await?;
    let mut endpoint = EndpointManager::new(&options).await?;
    loop {
        try_recv!(oneshot, upper_shutdown);
        let (stream, _) = service_listener.accept().await?;
        debug!("accepted http: {:?}", stream);
        let tunnel = do_!(
            do_!(
                timeout(Duration::from_secs(2), endpoint.connect()).await,
                continue
            ),
            {
                endpoint = do_!(
                    do_!(
                        timeout(Duration::from_secs(2), EndpointManager::new(&options)).await,
                        continue
                    ),
                    continue
                );
                continue;
            }
        );
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = options.password_hash.clone();
        let x = accept_client_request.clone();
        tokio::spawn(forward_through_quic(
            stream,
            shutdown_rx,
            tunnel,
            hash_copy,
            x,
        ));
    }
    Ok(())
}

// todo: refactor into Client class
async fn run_client(upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    // let (shutdown_tx, _) = broadcast::channel(1);
    let http_addr = options.local_http_addr.parse::<SocketAddr>()?;
    let socks5_addr = options.local_socks5_addr.parse::<SocketAddr>()?;
    let (shutdown1_tx, shutdown1_rx) = oneshot::channel();
    let (shutdown2_tx, shutdown2_rx) = oneshot::channel();
    tokio::spawn(user_endpoint_listener(
        shutdown1_rx,
        http_addr,
        options.clone(),
        accept_http_request,
    ));

    tokio::spawn(user_endpoint_listener(
        shutdown2_rx,
        socks5_addr,
        options,
        accept_sock5_request,
    ));
    let _ = upper_shutdown.await;
    Ok(())
}

// todo: refactor into Server class
async fn run_server(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let (endpoint, mut incoming) = quic_tunnel_rx(&options).await?;
    info!("listening on {}", endpoint.local_addr()?);
    while let Some(conn) = incoming.next().await {
        try_recv!(oneshot, upper_shutdown);
        debug!("connection incoming");
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = options.password_hash.clone();
        let quinn::NewConnection { bi_streams, .. } = conn.await?;
        debug!("connected");
        tokio::spawn(async move {
            handle_quic_connection(bi_streams, shutdown_rx, hash_copy)
                .await
                .unwrap_or_else(move |e| {
                    error!("connection failed: {reason}", reason = e.to_string())
                });
        });
    }
    Ok(())
}

pub async fn build_tunnel(ctrl_c: impl std::future::Future, options: Opt) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    if options.server {
        info!("server-start");
        select! {
            _ = ctrl_c => {
                info!("ctrl-c");
            }
            res = run_server(shutdown_rx, options) => {
                match res {
                    Err(err) => {
                        error!("server quit due to {:?}", err);
                    }
                    ok => {
                        info!("server end: {:?}", ok);
                    }
                }
            }
        }
    } else {
        info!("client-start");
        select! {
            _ = ctrl_c => {
                info!("ctrl-c");
            }
            res = run_client(shutdown_rx, options) => {
                match res {
                    Err(err) => {
                        error!("client quit due to {:?}", err);
                    }
                    ok => {
                        info!("client end: {:?}", ok);

                    }
                }
            }
        }
    }

    drop(shutdown_tx);
    Ok(())
}

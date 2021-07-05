use crate::{
    args::Opt,
    client::{http::*, socks5::*},
    server::trojan::*,
    tunnel::{get_server_local_addr, quic::*, tcp_tls::*},
    utils::{
        relay_tcp, relay_udp, ClientServerConnection, ClientTcpStream, ConnectionMode,
        ConnectionRequest, MixAddrType, Socks5UdpStream,
    },
};
use anyhow::Result;
use futures::StreamExt;
use lazy_static::lazy_static;
use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
    sync::{broadcast, oneshot},
};
use tokio_rustls::TlsAcceptor;
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

async fn forward<F, Fut, Connecting>(
    stream: TcpStream,
    upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    accept_client_request: F,
    connect_to_server: Connecting,
) -> Result<()>
where
    F: FnOnce(TcpStream) -> Fut + Send,
    Fut: Future<Output = ClientRequestAcceptResult> + Send,
    Connecting: Future<Output = Result<ClientServerConnection>> + Send,
{
    let (conn_req, addr) = accept_client_request(stream).await?;
    let mut outbound = connect_to_server.await.map_err(|e| {
        error!("forward error: {}", e);
        e
    })?;
    let conn_id = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);

    use ConnectionRequest::*;
    match conn_req {
        TCP(inbound) => {
            trojan_connect_tcp(&addr, &mut outbound, password_hash).await?;
            info!(
                "[tcp][{}]{:?} => {:?}",
                conn_id,
                inbound.peer_addr()?,
                &addr
            );
            relay_tcp(inbound, outbound, upper_shutdown).await;
            debug!("[end][tcp][{}]", conn_id);
        }
        UDP(inbound) => {
            trojan_connect_udp(&mut outbound, password_hash).await?;
            info!("[udp][{}] => {:?}", conn_id, &addr);
            relay_udp(inbound, outbound, upper_shutdown).await;
            info!("[end][udp][{}]", conn_id);
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

#[macro_export]
macro_rules! or_continue {
    ($res:expr) => {
        match $res {
            Ok(res) => res,
            Err(e) => {
                info!("{} failed due to {:?}", stringify!($res), e);
                continue;
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
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let service_listener = TcpListener::bind(&service_addr).await?;
    let hash = options.password_hash.clone();
    let remote_addr = options.remote_socket_addr;
    let domain_string = Arc::new(options.proxy_url.clone());

    let (task_tx, task_rx) = tokio::sync::mpsc::channel(20);
    tokio::spawn(quic_connection_daemon(options.clone(), task_rx));
    let tls_config = Arc::new(tls_client_config().await);

    loop {
        try_recv!(oneshot, upper_shutdown);
        let (stream, _) = service_listener.accept().await?;
        debug!("accepted http: {:?}", stream);
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = hash.clone();
        match &options.connection_mode {
            ConnectionMode::TcpTLS => {
                let tls_config_copy = tls_config.clone();
                let domain_string_copy = domain_string.clone();
                tokio::spawn(forward(
                    stream,
                    shutdown_rx,
                    hash_copy,
                    accept_client_request.clone(),
                    connect_through_tcp_tls(tls_config_copy, domain_string_copy, remote_addr),
                ));
            }
            ConnectionMode::Quic => {
                let (conn_ret_tx, conn_ret_rx) = oneshot::channel();
                or_continue!(task_tx.send(conn_ret_tx).await);
                tokio::spawn(forward(
                    stream,
                    shutdown_rx,
                    hash_copy,
                    accept_client_request.clone(),
                    async move { Ok(ClientServerConnection::Quic(conn_ret_rx.await??)) },
                ));
            }
        }
    }
    Ok(())
}

// todo: refactor into Client class
async fn run_client(upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    // let (shutdown_tx, _) = broadcast::channel(1);
    let http_addr = options.local_http_addr.parse::<SocketAddr>()?;
    let socks5_addr = options.local_socks5_addr.parse::<SocketAddr>()?;
    let (_shutdown1_tx, shutdown1_rx) = oneshot::channel();
    let (_shutdown2_tx, shutdown2_rx) = oneshot::channel();
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

async fn run_quic_server(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let (endpoint, mut incoming) = quic_tunnel_rx(&options).await?;
    info!("listening on {}", endpoint.local_addr()?);
    while let Some(conn) = incoming.next().await {
        try_recv!(oneshot, upper_shutdown);
        debug!("connection incoming");
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = options.password_hash.clone();
        let quinn::NewConnection { bi_streams, .. } = match conn.await {
            Ok(new_conn) => new_conn,
            Err(e) => {
                error!("error while awaiting connection {:?}", e);
                continue;
            }
        };
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

async fn run_tcp_tls_server(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let config = tls_server_config(&options).await?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let addr = get_server_local_addr(&options);
    let listener = TcpListener::bind(&addr).await?;
    loop {
        try_recv!(oneshot, upper_shutdown);
        let (stream, _peer_addr) = listener.accept().await?;
        let acceptor_copy = acceptor.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = options.password_hash.clone();
        tokio::spawn(handle_tcp_tls_connection(
            stream,
            acceptor_copy,
            shutdown_rx,
            hash_copy,
        ));
    }
    Ok(())
}

// todo: refactor into Server class
async fn run_server(upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (_shutdown_tx1, shutdown_rx1) = oneshot::channel();
    let (_shutdown_tx2, shutdown_rx2) = oneshot::channel();
    tokio::spawn(run_quic_server(shutdown_rx1, options.clone()));
    tokio::spawn(run_tcp_tls_server(shutdown_rx2, options));
    let _ = upper_shutdown.await;
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

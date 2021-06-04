use crate::{
    args::Opt,
    client::{http::*, socks5::*},
    server::trojan::*,
    tunnel::quic::*,
    utils::{copy_udp, new_trojan_udp_stream, ConnectionRequest},
};
use anyhow::Result;
use futures::StreamExt;
use quinn::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{broadcast, oneshot};
use tracing::*;

macro_rules! create_forward_through_quic {
    ($fn_name:ident, $request_type:ident) => {
        async fn $fn_name(
            stream: TcpStream,
            mut upper_shutdown: broadcast::Receiver<()>,
            tunnel: (SendStream, RecvStream),
            password_hash: Arc<String>,
        ) -> Result<()> {
            let mut req = $request_type::new();
            let (mut out_write, mut out_read) = tunnel;
            let conn_req = req.accept(stream).await?;

            use ConnectionRequest::*;
            match conn_req {
                TCP(mut stream) => {
                    trojan_connect_tcp(req.addr(), &mut out_write, password_hash).await?;
                    info!("[tcp]{:?} => {:?}", stream.peer_addr()?, req.addr());
                    let (mut in_read, mut in_write) = stream.split();
                    select! {
                        _ = tokio::io::copy(&mut out_read, &mut in_write) => {
                            debug!("tcp relaying upload end");
                        },
                        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
                            debug!("tcp relaying download end");
                        },
                        _ = upper_shutdown.recv() => {
                            debug!("shutdown signal received");
                        },
                    }
                }
                UDP(mut udp) => {
                    trojan_connect_udp(&mut out_write, password_hash).await?;
                    let (mut in_write, mut in_read) = udp.split();
                    let (mut out_write, mut out_read) = new_trojan_udp_stream(out_write, out_read);
                    info!("[udp] => {:?}", req.addr());
                    select! {
                        _ = copy_udp(&mut out_read, &mut in_write) => {
                            debug!("udp relaying upload end");
                        },
                        _ = copy_udp(&mut in_read, &mut out_write) => {
                            debug!("udp relaying download end");
                        },
                        _ = upper_shutdown.recv() => {
                            debug!("shutdown signal received");
                        },
                    }
                }
            }

            Ok(())
        }
    };
}

create_forward_through_quic!(forward_http_through_quic, HttpRequest);
create_forward_through_quic!(forward_socks5_through_quic, Socks5Request);

#[macro_export]
macro_rules! try_recv {
    ($T:tt, $instance:expr) => {
        try_recv!($T, $instance, break)
    };
    ($T:tt, $instance:expr, $then_expr:expr) => {
        match $instance.try_recv() {
            Err($T::error::TryRecvError::Empty) => (),
            _ => {
                $then_expr;
            }
        }
    };
}

// todo: refactor into Client class
async fn run_client(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let mut endpoint = EndpointManager::new(&options).await?;
    let http_addr = options.local_http_addr.parse::<SocketAddr>()?;
    let http_listener = TcpListener::bind(&http_addr).await?;

    let socks5_addr = options.local_socks5_addr.parse::<SocketAddr>()?;
    let socks5_listener = TcpListener::bind(&socks5_addr).await?;
    loop {
        try_recv!(oneshot, upper_shutdown);
        select! {
            acc = http_listener.accept() => {
                let (stream, _) = acc?;
                debug!("accepted http: {:?}", stream);
                let tunnel = endpoint.connect().await?;
                let shutdown_rx = shutdown_tx.subscribe();
                let hash_copy = options.password_hash.clone();
                tokio::spawn(async move {
                    let _ = forward_http_through_quic(stream, shutdown_rx, tunnel, hash_copy).await;
                });
            },
            acc = socks5_listener.accept() => {
                let (stream, _) = acc?;
                debug!("accepted socks5: {:?}", stream);
                let tunnel = endpoint.connect().await?;
                let shutdown_rx = shutdown_tx.subscribe();
                let hash_copy = options.password_hash.clone();
                tokio::spawn(async move {
                    let _ = forward_socks5_through_quic(stream, shutdown_rx, tunnel, hash_copy).await;
                });
            },
        };
    }
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
                    _ => {}
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
                    _ => {}
                }
            }
        }
    }

    drop(shutdown_tx);
    Ok(())
}

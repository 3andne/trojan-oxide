use crate::{
    args::Opt, client::{http::*, socks5::*}, server::trojan::*, tunnel::quic::*, utils::ClientUdpStream,
};
use anyhow::Result;
use futures::StreamExt;
use quinn::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{broadcast, oneshot};
use tracing::*;

pub enum ConnectionRequest {
    TCP,
    UDP(ClientUdpStream),
}

macro_rules! create_forward_through_quic {
    ($fn_name:ident, $request_type:ident) => {
        async fn $fn_name(
            mut stream: TcpStream,
            mut upper_shutdown: broadcast::Receiver<()>,
            tunnel: (SendStream, RecvStream),
            password_hash: Arc<String>,
        ) -> Result<()> {
            let mut req = $request_type::new();
            let (mut out_write, mut out_read) = tunnel;
            let conn_req = req.accept(&mut stream).await?;
        
            req.send_packet0(&mut out_write, password_hash).await?;
        
            use ConnectionRequest::*;
            match conn_req {
                TCP => {
                    info!("[tcp]{:?} => {:?}", stream.peer_addr()?, req.addr());
                    let (mut in_read, mut in_write) = stream.split();
                    select! {
                        _ = tokio::io::copy(&mut out_read, &mut in_write) => {
                            debug!("relaying upload end");
                        },
                        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
                            debug!("relaying download end");
                        },
                        _ = upper_shutdown.recv() => {
                            debug!("shutdown signal received");
                        },
                    }
                }
                UDP(udp) => {
                    let (mut in_read, mut in_write) = udp.split();
                    info!("[udp] => {:?}", req.addr());
                    let mut dummy = [0; 2];
                    select! {
                        _ = tokio::io::copy(&mut out_read, &mut in_write) => {
                            debug!("relaying upload end");
                        },
                        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
                            debug!("relaying download end");
                        },
                        _ = upper_shutdown.recv() => {
                            debug!("shutdown signal received");
                        },
                        _ = stream.read(&mut dummy) => {
                            debug!("udp shutdown");
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


async fn run_client(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let mut quic_tx = quic_tunnel_tx(&options).await?;
    let addr = options.local_addr.parse::<SocketAddr>()?;
    let listener = TcpListener::bind(&addr).await?;
    loop {
        match upper_shutdown.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => (),
            _ => {
                break;
            }
        }
        let (stream, _) = listener.accept().await?;
        debug!("accepted tcp: {:?}", stream);

        let tunnel = match quic_tx.open_bi().await {
            Ok(t) => t,
            Err(e) => {
                error!("{}", e);
                quic_tx = quic_tunnel_tx(&options).await?;
                quic_tx.open_bi().await?
            }
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = options.password_hash.clone();
        tokio::spawn(async move {
            let _ = forward_http_through_quic(stream, shutdown_rx, tunnel, hash_copy).await;
        });
    }
    Ok(())
}

async fn run_server(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let (endpoint, mut incoming) = quic_tunnel_rx(&options).await?;
    info!("listening on {}", endpoint.local_addr()?);
    while let Some(conn) = incoming.next().await {
        match upper_shutdown.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => (),
            _ => {
                break;
            }
        }
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
    todo!()
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

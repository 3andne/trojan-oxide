use crate::{args::Opt, client::http::*, server::trojan::*, tunnel::quic::*};
use anyhow::Result;
use futures::StreamExt;
use quinn::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{broadcast, oneshot};
use tracing::*;

async fn forward_through_quic(
    mut stream: TcpStream,
    mut upper_shutdown: broadcast::Receiver<()>,
    tunnel: (SendStream, RecvStream),
    password_hash: Arc<String>,
) -> Result<()> {
    let mut target = Target::new();
    let (mut out_write, mut out_read) = tunnel;
    target.accept(&mut stream).await?;

    target.send_packet0(&mut out_write, password_hash).await?;

    let (mut in_read, mut in_write) = stream.split();

    trace!("start relaying");
    select! {
        _ = tokio::io::copy(&mut out_read, &mut in_write) => {
            trace!("relaying upload end");
        },
        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
            trace!("relaying download end");
        },
        _ = upper_shutdown.recv() => {
            trace!("shutdown signal received");
        },
    }
    Ok(())
}

async fn run_client(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let mut quic_tx = quic_tunnel_tx(&options).await.map_err(|e| {
        trace!("quic_tunnel_tx failed due to {:?}", e);
        e
    })?;
    let addr = options.local_addr.parse::<SocketAddr>().map_err(|e| {
        trace!("local_addr.parse failed due to {:?}", e);
        e
    })?;
    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        trace!("TcpListener::bind local addr failed due to {:?}", e);
        e
    })?;
    loop {
        match upper_shutdown.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => (),
            _ => {
                break;
            }
        }
        let (stream, _) = listener.accept().await?;
        trace!("accepted tcp: {:?}", stream);
        let tunnel = match quic_tx.open_bi().await {
            Ok(t) => t,
            Err(e) => {
                trace!("{}", e);
                quic_tx = quic_tunnel_tx(&options).await?;
                quic_tx.open_bi().await?
            }
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = options.password_hash.clone();
        tokio::spawn(async move {
            let _ = forward_through_quic(stream, shutdown_rx, tunnel, hash_copy).await;
        });
    }
    Ok(())
}

async fn run_server(mut upper_shutdown: oneshot::Receiver<()>, options: Opt) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let (_, mut incoming) = quic_tunnel_rx(&options).await?;
    trace!("quic_tunnel_rx() built");
    while let Some(conn) = incoming.next().await {
        match upper_shutdown.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => (),
            _ => {
                break;
            }
        }
        trace!("connection incoming");
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = options.password_hash.clone();
        let quinn::NewConnection { bi_streams, .. } = conn.await?;
        trace!("connected");
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
                        trace!("server quit due to {:?}", err);
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
                        trace!("client quit due to {:?}", err);
                    }
                    _ => {}
                }
            }
        }
    }

    drop(shutdown_tx);
    Ok(())
}

use crate::{args::Opt, client::http::*, server::trojan::*, tunnel::quic::*};
use anyhow::Result;
use futures::{ready, StreamExt};
use quinn::*;
use std::sync::Arc;
use std::{net::SocketAddr, task::Poll};
use tokio::select;
use tokio::sync::{broadcast, oneshot};
use tokio::{
    io::AsyncRead,
    net::{TcpListener, TcpStream, UdpSocket},
};
use tracing::*;

pub enum ConnectionRequest {
    TCP,
    UDP(ClientUdpStream),
}

pub struct ClientUdpStream {
    server_udp_socket: Arc<UdpSocket>,
    client_udp_addr: Option<SocketAddr>,
}

impl ClientUdpStream {
    pub fn new(server_udp_socket: Arc<UdpSocket>) -> Self {
        Self {
            server_udp_socket,
            client_udp_addr: None,
        }
    }
}

impl AsyncRead for ClientUdpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let addr = match ready!(self.server_udp_socket.poll_recv_from(cx, buf)) {
            Ok(addr) => addr,
            Err(e) => {
                return Poll::Ready(Err(e));
            }
        };
        ;
        todo!()
    }
}

async fn forward_through_quic(
    mut stream: TcpStream,
    mut upper_shutdown: broadcast::Receiver<()>,
    tunnel: (SendStream, RecvStream),
    password_hash: Arc<String>,
) -> Result<()> {
    let mut req = HttpRequest::new();
    let (mut out_write, mut out_read) = tunnel;
    let conn_req = req.accept(&mut stream).await?;

    req.send_packet0(&mut out_write, password_hash).await?;

    use ConnectionRequest::*;
    match conn_req {
        TCP => {
            info!("[tcp]{:?} => {:?}", stream.peer_addr()?, req.addr);
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
        UDP(udp) => {}
    }

    Ok(())
}

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
            let _ = forward_through_quic(stream, shutdown_rx, tunnel, hash_copy).await;
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

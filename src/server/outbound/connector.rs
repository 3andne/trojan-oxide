#[cfg(feature = "udp")]
use crate::utils::{copy_udp, ServerUdpStream};
use crate::{
    server::inbound::{SplitableToAsyncReadWrite, TrojanAcceptor},
    utils::{copy_tcp, ConnectionRequest},
};
use anyhow::Result;
use lazy_static::lazy_static;
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[cfg(feature = "udp")]
use tokio::net::UdpSocket;
use tokio::{net::TcpStream, select, sync::broadcast};
use tracing::{debug, info};

lazy_static! {
    static ref CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
}

pub async fn handle_outbound<I>(
    stream: I,
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    fallback_port: Arc<String>,
) -> Result<()>
where
    I: SplitableToAsyncReadWrite + Debug + Unpin,
{
    let mut target = TrojanAcceptor::new(password_hash.as_bytes(), fallback_port);
    use ConnectionRequest::*;
    match target.accept(stream).await {
        Ok(TCP((mut in_write, mut in_read))) => {
            let mut outbound = if target.host.is_ip() {
                TcpStream::connect(target.host.to_socket_addrs()).await?
            } else {
                TcpStream::connect(target.host.host_repr()).await?
            };
            // outbound.set_nodelay(true)?;
            debug!("outbound connected: {:?}", outbound);

            let (mut out_read, mut out_write) = outbound.split();
            let conn_id = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            info!("[tcp][{}]start relaying", conn_id);
            // FUUUUUCK YOU tokio::io::copy, you buggy little shit.
            select! {
                _ = copy_tcp(&mut out_read, &mut in_write) => {
                    debug!("server relaying download end");
                },
                _ = tokio::io::copy(&mut in_read, &mut out_write) => {
                    debug!("server relaying upload end");
                },
                _ = upper_shutdown.recv() => {
                    debug!("server shutdown signal received");
                },
            }
            debug!("[tcp][{}]end relaying", conn_id);
        }
        #[cfg(feature = "udp")]
        Ok(UDP((mut in_write, mut in_read))) => {
            let outbound = UdpSocket::bind("[::]:0").await?;
            info!("[udp] {:?} =>", outbound.local_addr());
            let mut udp_stream = ServerUdpStream::new(outbound);
            let (mut out_write, mut out_read) = udp_stream.split();
            select! {
                res = copy_udp(&mut out_read, &mut in_write) => {
                    debug!("udp relaying download end: {:?}", res);
                },
                res = copy_udp(&mut in_read, &mut out_write) => {
                    debug!("udp relaying upload end: {:?}", res);
                },
            }
        }
        #[cfg(feature = "quic")]
        Ok(ECHO((mut in_write, mut in_read))) => {
            info!("[echo]start relaying");
            select! {
                _ = tokio::io::copy(&mut in_read, &mut in_write) => {
                    debug!("server relaying upload end");
                },
                _ = upper_shutdown.recv() => {
                    debug!("server shutdown signal received");
                },
            }
            info!("[echo]end relaying");
        }
        Err(e) => {
            info!("invalid connection: {}", e);
        }
    }

    Ok(())
}

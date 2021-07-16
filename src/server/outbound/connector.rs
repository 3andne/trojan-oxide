use crate::{
    server::inbound::{SplitableToAsyncReadWrite, TrojanAcceptor},
    utils::{copy_tcp, ConnectionRequest},
};
use anyhow::{anyhow, Context, Error, Result};
use lazy_static::lazy_static;
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::{net::TcpStream, select, sync::broadcast};
use tracing::{debug, info};
#[cfg(feature = "udp")]
use {
    crate::utils::{copy_udp, ServerUdpStream},
    tokio::net::UdpSocket,
};

lazy_static! {
    static ref TCP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
    static ref UDP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
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
                TcpStream::connect(target.host.to_socket_addrs()).await
            } else {
                TcpStream::connect(target.host.host_repr()).await
            }
            .map_err(|e| Error::new(e))
            .with_context(|| anyhow!("failed to connect to {:?}", target.host))?;

            outbound
                .set_nodelay(true)
                .map_err(|e| Error::new(e))
                .with_context(|| {
                    anyhow!(
                        "failed to set tcp_nodelay for outbound stream {:?}",
                        target.host
                    )
                })?;

            #[cfg(feature = "debug_info")]
            debug!("outbound connected: {:?}", outbound);

            let (mut out_read, mut out_write) = outbound.split();
            let conn_id = TCP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            info!("[tcp][{}] => {:?}", conn_id, &target.host);
            // FUUUUUCK YOU tokio::io::copy, you buggy little shit.
            select! {
                _ = copy_tcp(&mut out_read, &mut in_write) => {
                    info!("[tcp][{}]end downloading", conn_id);
                },
                _ = tokio::io::copy(&mut in_read, &mut out_write) => {
                    info!("[tcp][{}]end uploading", conn_id);
                },
                _ = upper_shutdown.recv() => {
                    info!("[tcp][{}]shutdown signal received", conn_id);
                },
            }
        }
        #[cfg(feature = "udp")]
        Ok(UDP((mut in_write, mut in_read))) => {
            let outbound = UdpSocket::bind("[::]:0")
                .await
                .map_err(|e| Error::new(e))
                .with_context(|| anyhow!("failed to bind UdpSocket {:?}", target.host))?;

            let conn_id = UDP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            debug!("[udp][{}] {:?} =>", conn_id, outbound.local_addr());
            let mut udp_stream = ServerUdpStream::new(outbound);
            let (mut out_write, mut out_read) = udp_stream.split();
            select! {
                res = copy_udp(&mut out_read, &mut in_write, None) => {
                    info!("[udp][{}]udp relaying download end: {:?}", conn_id, res);
                },
                res = copy_udp(&mut in_read, &mut out_write, Some(conn_id)) => {
                    info!("[udp][{}]udp relaying upload end: {:?}", conn_id, res);
                },
                _ = upper_shutdown.recv() => {
                    info!("[udp][{}]shutdown signal received", conn_id);
                },
            }
        }
        #[cfg(feature = "quic")]
        Ok(ECHO((mut in_write, mut in_read))) => {
            debug!("[echo]start relaying");
            select! {
                _ = tokio::io::copy(&mut in_read, &mut in_write) => {
                    debug!("server relaying upload end");
                },
                _ = upper_shutdown.recv() => {
                    debug!("server shutdown signal received");
                },
            }
            debug!("[echo]end relaying");
        }
        Err(e) => {
            return Err(
                Error::new(e).context(anyhow!("failed to parse connection to {:?}", target.host))
            );
        }
    }

    Ok(())
}

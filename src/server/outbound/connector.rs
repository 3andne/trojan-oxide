use crate::{
    adapt,
    protocol::{SERVER_OUTBOUND_CONNECT_TIMEOUT, TCP_MAX_IDLE_TIMEOUT},
    server::inbound::TrojanAcceptor,
    utils::{lite_tls::LeaveTls, Adapter, ConnectionRequest, MixAddrType, Splitable},
};
use anyhow::{anyhow, Context, Error, Result};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    select,
    sync::broadcast,
    time::{timeout, Duration},
};
use tracing::{debug, info};
#[cfg(feature = "udp")]
use {crate::server::utils::ServerUdpStream, tokio::net::UdpSocket};

pub(crate) static TCP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
pub(crate) static UDP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);

async fn outbound_connect(target_host: &MixAddrType) -> Result<TcpStream> {
    let outbound = if target_host.is_ip() {
        TcpStream::connect(target_host.to_socket_addrs()).await
    } else {
        TcpStream::connect(target_host.host_repr()).await
    }
    .map_err(|e| Error::new(e))
    .with_context(|| anyhow!("failed to connect to {:?}", target_host))?;

    outbound
        .set_nodelay(true)
        .map_err(|e| Error::new(e))
        .with_context(|| {
            anyhow!(
                "failed to set tcp_nodelay for outbound stream {:?}",
                target_host
            )
        })?;
    Ok(outbound)
}

pub async fn handle_outbound<I>(
    stream: I,
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    fallback_port: Arc<String>,
) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Splitable + LeaveTls + Unpin + Send + 'static,
{
    let mut target = TrojanAcceptor::new(password_hash.as_bytes(), fallback_port);
    use ConnectionRequest::*;
    match timeout(
        Duration::from_secs(SERVER_OUTBOUND_CONNECT_TIMEOUT),
        target.accept(stream),
    )
    .await?
    {
        Ok(TCP(inbound)) => {
            let outbound =
                timeout(Duration::from_secs(2), outbound_connect(&target.host)).await??;
            let conn_id = TCP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            inbound
                .forward(outbound, &target.host, upper_shutdown, conn_id)
                .await?;
        }
        #[cfg(feature = "udp")]
        Ok(UDP(inbound)) => {
            let outbound = UdpSocket::bind("[::]:0")
                .await
                .map_err(|e| Error::new(e))
                .with_context(|| anyhow!("failed to bind UdpSocket {:?}", target.host))?;

            let mut outbound = ServerUdpStream::new(outbound);
            let conn_id = UDP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            adapt!([udp][conn_id]
                inbound <=> outbound
                Until upper_shutdown Or Sec TCP_MAX_IDLE_TIMEOUT
            );
        }
        #[cfg(feature = "quic")]
        Ok(ECHO(inbound)) => {
            let (mut in_read, mut in_write) = inbound.split();
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
        Ok(_PHANTOM(_)) => {
            unreachable!("")
        }
        Err(e) => {
            return Err(Error::new(e))
                .with_context(|| anyhow!("failed to parse connection to {:?}", target.host));
        }
    }

    Ok(())
}

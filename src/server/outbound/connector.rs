use crate::{
    adapt,
    args::TrojanContext,
    protocol::{SERVER_OUTBOUND_CONNECT_TIMEOUT, TCP_MAX_IDLE_TIMEOUT},
    server::inbound::TrojanAcceptor,
    utils::{lite_tls::LeaveTls, Adapter, ConnectionRequest, MixAddrType},
};
use anyhow::{anyhow, Context, Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    select,
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

pub async fn handle_outbound<I>(mut context: TrojanContext, stream: I) -> Result<()>
where
    I: AsyncRead + AsyncWrite + LeaveTls + Unpin + Send + 'static,
{
    let opt = &*context.options;
    let mut target = TrojanAcceptor::new(opt.password_hash.as_bytes(), opt.fallback_port);
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
                .forward(outbound, &target.host, context.shutdown, conn_id)
                .await?;
        }
        #[cfg(feature = "udp")]
        Ok(UDP(inbound)) => {
            let outbound = UdpSocket::bind("[::]:0")
                .await
                .map_err(|e| Error::new(e))
                .with_context(|| anyhow!("failed to bind UdpSocket {:?}", target.host))?;

            let outbound = ServerUdpStream::new(outbound);
            let conn_id = UDP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            let shutdown = context.shutdown;
            adapt!([udp][conn_id]
                inbound <=> outbound
                Until shutdown Or Sec TCP_MAX_IDLE_TIMEOUT
            );
        }
        #[cfg(feature = "quic")]
        Ok(ECHO(mut inbound)) => {
            use tokio::io::AsyncReadExt;
            use tokio::io::AsyncWriteExt;
            let echo = async move {
                let mut buf = [0; 256];
                loop {
                    let num = inbound.read(&mut buf).await;
                    let num = if num.is_err() { return } else { num.unwrap() };
                    if inbound.write(&buf[..num]).await.is_err() {
                        return;
                    }
                }
            };
            debug!("[echo]start relaying");
            select! {
                _ = echo => {
                    debug!("echo end");
                },
                _ = context.shutdown.recv() => {
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

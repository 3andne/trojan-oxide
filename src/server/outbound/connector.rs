use crate::{
    server::{
        inbound::{TcpOption, TrojanAcceptor},
        outbound::utils::{outbound_connect, relay_tcp},
        Splitable,
    },
    utils::{
        lite_tls::{LeaveTls, LiteTlsStream},
        ConnectionRequest, ParserError, TimeoutMonitor,
    },
};
use anyhow::{anyhow, Context, Error, Result};
use lazy_static::lazy_static;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    select,
    sync::broadcast,
};
use tracing::{debug, info};
#[cfg(feature = "udp")]
use {
    crate::utils::{copy_udp, ServerUdpStream},
    tokio::net::UdpSocket,
};

lazy_static! {
    pub(crate) static ref TCP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static ref UDP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
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
    use TcpOption::*;
    match target.accept(stream).await {
        Ok(TCP(TLS(inbound))) => {
            let outbound = outbound_connect(&target.host).await?;

            #[cfg(feature = "debug_info")]
            debug!("outbound connected: {:?}", outbound);

            relay_tcp(inbound, outbound, &target.host, upper_shutdown).await;
        }
        Ok(TCP(LiteTLS(mut inbound))) => {
            let mut outbound = outbound_connect(&target.host).await?;
            let mut lite_tls_endpoint = LiteTlsStream::new_server_endpoint();
            match lite_tls_endpoint
                .handshake(&mut outbound, &mut inbound)
                .await
            {
                Ok(_) => {
                    lite_tls_endpoint.flush(&mut outbound, &mut inbound).await?;
                    let inbound = inbound.into_inner().leave();
                    relay_tcp(inbound, outbound, &target.host, upper_shutdown).await;
                }
                Err(e) => {
                    if let Some(ParserError::Invalid(x)) = e.downcast_ref::<ParserError>() {
                        debug!("not tls stream: {}", x);
                        lite_tls_endpoint.flush(&mut outbound, &mut inbound).await?;

                        relay_tcp(inbound, outbound, &target.host, upper_shutdown).await;
                    }
                }
            }
        }
        #[cfg(feature = "udp")]
        Ok(UDP(inbound)) => {
            let (mut in_write, mut in_read) = inbound.split();
            let outbound = UdpSocket::bind("[::]:0")
                .await
                .map_err(|e| Error::new(e))
                .with_context(|| anyhow!("failed to bind UdpSocket {:?}", target.host))?;

            let conn_id = UDP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            debug!("[udp][{}] {:?} =>", conn_id, outbound.local_addr());
            let mut udp_stream = ServerUdpStream::new(outbound);
            let (out_write, out_read) = udp_stream.split();
            let timeout_monitor = TimeoutMonitor::new(Duration::from_secs(5 * 60));
            let mut out_read = timeout_monitor.watch(out_read);
            let mut out_write = timeout_monitor.watch(out_write);
            select! {
                res = copy_udp(&mut out_read, &mut in_write, None) => {
                    info!("[udp][{}]end downloading: {:?}", conn_id, res);
                },
                res = copy_udp(&mut in_read, &mut out_write, Some(conn_id)) => {
                    info!("[udp][{}]end uploading: {:?}", conn_id, res);
                },
                _ = timeout_monitor => {
                    info!("[udp][{}]end timeout", conn_id);
                }
                _ = upper_shutdown.recv() => {
                    info!("[udp][{}]shutdown signal received", conn_id);
                },
            }
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
            return Err(
                Error::new(e).context(anyhow!("failed to parse connection to {:?}", target.host))
            );
        }
    }

    Ok(())
}

use crate::server::outbound::handle_outbound;
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio::sync::broadcast;
#[cfg(feature = "quic")]
use {
    futures::{StreamExt, TryFutureExt},
    quinn::*,
};

#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use {tokio::net::TcpStream, tokio_rustls::TlsAcceptor};

#[cfg(feature = "quic")]
pub async fn handle_quic_connection(
    mut streams: IncomingBiStreams,
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    fallback_port: Arc<String>,
) -> Result<()> {
    use crate::utils::WRTuple;
    use tokio::select;
    use tracing::{error, info};
    let (shutdown_tx, _) = broadcast::channel(1);

    loop {
        let stream = select! {
            s = streams.next() => {
                match s {
                    Some(stream) => stream,
                    None => {break;}
                }
            },
            _ = upper_shutdown.recv() => {
                // info
                break;
            }
        };

        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::Error::new(e));
            }
            Ok(s) => s,
        };
        let shutdown = shutdown_tx.subscribe();
        let pass_copy = password_hash.clone();
        let fallback_port_clone = fallback_port.clone();
        tokio::spawn(
            handle_outbound(
                WRTuple::from_wr_tuple(stream),
                shutdown,
                pass_copy,
                fallback_port_clone,
            )
            .map_err(|e| {
                error!("handle_quic_outbound quit due to {:#}", e);
                e
            }),
        );
    }
    Ok(())
}

#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
pub async fn handle_tcp_tls_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    fallback_port: Arc<String>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let stream = acceptor
        .accept(stream)
        .await
        .with_context(|| anyhow!("failed to accept TlsStream"))?;
    handle_outbound(stream, upper_shutdown, password_hash, fallback_port).await?;
    Ok(())
}

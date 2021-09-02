use crate::{args::TrojanContext, server::outbound::handle_outbound};
use anyhow::{anyhow, Context, Result};
use tokio::{
    sync::broadcast,
    time::{timeout, Duration},
};
use tokio_rustls::Accept;
#[cfg(feature = "quic")]
use {
    futures::{StreamExt, TryFutureExt},
    quinn::*,
};

#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use tokio::net::TcpStream;

#[cfg(feature = "quic")]
pub async fn handle_quic_connection(
    mut context: TrojanContext,
    mut streams: IncomingBiStreams,
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
            _ = context.shutdown.recv() => {
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
        tokio::spawn(
            handle_outbound(
                context.clone_with_signal(shutdown_tx.subscribe()),
                WRTuple::from_wr_tuple(stream),
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
    context: TrojanContext,
    incoming: Accept<TcpStream>,
    // upper_shutdown: broadcast::Receiver<()>,
    // password_hash: Arc<String>,
    // fallback_port: Arc<String>,
) -> Result<()> {
    let stream = timeout(Duration::from_secs(5), incoming)
        .await
        .with_context(|| anyhow!("failed to accept TlsStream"))??;
    handle_outbound(context, stream).await?;
    Ok(())
}

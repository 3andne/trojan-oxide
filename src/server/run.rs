#[cfg(feature = "quic")]
use crate::server::inbound::quic_listener;
#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use crate::server::inbound::tcp_tls_listener;

use crate::args::TrojanContext;
use anyhow::Result;
use futures::TryFutureExt;
use tracing::error;

// todo: refactor into Server class
#[cfg(feature = "server")]
pub async fn run_server(mut context: TrojanContext) -> Result<()> {
    use tokio::sync::broadcast;

    let (shutdown_tx, shutdown) = broadcast::channel(1);
    #[cfg(feature = "quic")]
    tokio::spawn(
        quic_listener(context.clone_with_signal(shutdown))
            .unwrap_or_else(move |e| error!("quic server shutdown due to {:#}", e)),
    );

    #[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
    tokio::spawn(
        tcp_tls_listener(context.clone_with_signal(shutdown_tx.subscribe()))
            .unwrap_or_else(move |e| error!("tcp_tls server shutdown due to {:#}", e)),
    );
    let _ = context.shutdown.recv().await;
    Ok(())
}

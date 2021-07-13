#[cfg(feature = "quic")]
use crate::server::inbound::quic_listener;
#[cfg(feature = "tcp_tls")]
use crate::server::inbound::tcp_tls_listener;

use crate::args::TrojanContext;
use anyhow::Result;
use tokio::sync::oneshot;

// todo: refactor into Server class
#[cfg(feature = "server")]
pub async fn run_server(
    upper_shutdown: oneshot::Receiver<()>,
    context: TrojanContext,
) -> Result<()> {
    #[cfg(feature = "quic")]
    let (_shutdown_tx1, shutdown_rx1) = oneshot::channel();
    #[cfg(feature = "quic")]
    tokio::spawn(quic_listener(shutdown_rx1, context.clone()));
    #[cfg(feature = "tcp_tls")]
    let (_shutdown_tx2, shutdown_rx2) = oneshot::channel();
    #[cfg(feature = "tcp_tls")]
    tokio::spawn(tcp_tls_listener(shutdown_rx2, context));
    let _ = upper_shutdown.await;
    Ok(())
}

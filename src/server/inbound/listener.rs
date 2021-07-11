use crate::{
    args::TrojanContext,
    server::inbound::handler::handle_tcp_tls_connection,
    try_recv,
    tunnel::{get_server_local_addr, tcp_tls::*},
};
#[cfg(feature = "quic")]
use crate::{server::inbound::handler::handle_quic_connection, tunnel::quic::*};
use anyhow::Result;
use futures::StreamExt;
use std::sync::Arc;
use tokio::{
    net::TcpListener,
    sync::{broadcast, oneshot},
};
use tokio_rustls::TlsAcceptor;
use tracing::*;

#[cfg(feature = "quic")]
pub async fn quic_listener(
    mut upper_shutdown: oneshot::Receiver<()>,
    context: TrojanContext,
) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let (endpoint, mut incoming) = quic_tunnel_rx(&context.options).await?;
    info!("listening on {}", endpoint.local_addr()?);
    while let Some(conn) = incoming.next().await {
        try_recv!(oneshot, upper_shutdown);
        debug!("connection incoming");
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = context.options.password_hash.clone();
        let fallback_port = context.options.fallback_port.clone();

        let quinn::NewConnection { bi_streams, .. } = match conn.await {
            Ok(new_conn) => new_conn,
            Err(e) => {
                error!("error while awaiting connection {:?}", e);
                continue;
            }
        };
        debug!("connected");
        tokio::spawn(async move {
            handle_quic_connection(bi_streams, shutdown_rx, hash_copy, fallback_port)
                .await
                .unwrap_or_else(move |e| {
                    error!("connection failed: {reason}", reason = e.to_string())
                });
        });
    }
    Ok(())
}

pub async fn tcp_tls_listener(
    mut upper_shutdown: oneshot::Receiver<()>,
    context: TrojanContext,
) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let config = tls_server_config(&context.options).await?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let addr = get_server_local_addr(&context.options);
    let listener = TcpListener::bind(&addr).await?;
    loop {
        try_recv!(oneshot, upper_shutdown);
        let (stream, _peer_addr) = listener.accept().await?;
        let acceptor_copy = acceptor.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = context.options.password_hash.clone();
        let fallback_port = context.options.fallback_port.clone();
        tokio::spawn(handle_tcp_tls_connection(
            stream,
            acceptor_copy,
            shutdown_rx,
            hash_copy,
            fallback_port,
        ));
    }
    Ok(())
}

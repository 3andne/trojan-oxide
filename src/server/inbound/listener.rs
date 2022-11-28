use crate::{args::TrojanContext, try_recv};

#[cfg(feature = "quic")]
use crate::{
    server::inbound::handler::handle_quic_connection, server::inbound::quic::quic_tunnel_rx,
};

use anyhow::{anyhow, Context, Result};
use futures::TryFutureExt;
use tokio::sync::broadcast;
use tracing::*;

#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use {
    crate::server::inbound::{
        get_server_local_addr,
        {handler::handle_tcp_tls_connection, tcp_tls::*},
    },
    std::sync::Arc,
    tokio::net::TcpListener,
    tokio_rustls::TlsAcceptor,
};

#[cfg(feature = "quic")]
pub async fn quic_listener(mut context: TrojanContext) -> Result<()> {
    use futures::StreamExt;
    let (shutdown_tx, _) = broadcast::channel(1);
    let (endpoint, mut incoming) = quic_tunnel_rx(&context.options).await?;
    info!("listening on [udp]{}", endpoint.local_addr()?);
    while let Some(conn) = incoming.next().await {
        try_recv!(broadcast, context.shutdown);
        debug!("[quic]connection incoming");

        let quinn::NewConnection { bi_streams, .. } = match conn.await {
            Ok(new_conn) => new_conn,
            Err(e) => {
                error!("[quic]error while awaiting connection {:#}", e);
                continue;
            }
        };
        tokio::spawn(
            handle_quic_connection(
                context.clone_with_signal(shutdown_tx.subscribe()),
                bi_streams,
            )
            .map_err(move |e| error!("[quic]connection failed: {:#}", e)),
        );
    }
    Ok(())
}

#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
pub async fn tcp_tls_listener(mut context: TrojanContext) -> Result<()> {
    use crate::server::utils::time_aligned_tcp_stream::TimeAlignedTcpStream;

    let (shutdown_tx, _) = broadcast::channel(1);
    let config = tls_server_config(&context.options)
        .await
        .with_context(|| anyhow!("failed to get config"))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let addr = get_server_local_addr(context.options.server_port);
    let mut listener = TcpListener::bind(&addr)
        .await
        .with_context(|| anyhow!("failed to bind tcp port"))?;
    info!("listening on [tcp]{}", listener.local_addr()?);
    loop {
        try_recv!(broadcast, context.shutdown);
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(err) => {
                error!("failed to listen to tcp: {:?}", err);
                drop(listener);
                listener = TcpListener::bind(&addr)
                    .await
                    .with_context(|| anyhow!("[tcp]failed to bind tcp port"))?;
                continue;
            }
        };
        stream.set_nodelay(true)?;
        let stream = TimeAlignedTcpStream::new(stream);
        tokio::spawn(
            handle_tcp_tls_connection(
                context.clone_with_signal(shutdown_tx.subscribe()),
                acceptor.accept(stream),
            )
            .unwrap_or_else(move |e| error!("[tcp]failed to handle connection: {:#}", e)),
        );
    }
    Ok(())
}

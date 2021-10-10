use crate::{
    args::TrojanContext,
    client::{
        outbound::forward,
        utils::{ClientConnectionRequest, ClientServerConnection},
        ConnectionMode,
    },
    or_continue, try_recv,
    utils::MixAddrType,
};

#[cfg(feature = "quic")]
use crate::client::outbound::quic::*;
#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use crate::client::outbound::tcp_tls::*;
use anyhow::Result;
use futures::TryFutureExt;
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{broadcast, oneshot},
};
use tracing::*;

pub type ClientRequestAcceptResult = Result<(ClientConnectionRequest, MixAddrType)>;

pub trait RequestFromClient {
    type Accepting<'a>: Future<Output = ClientRequestAcceptResult> + Send;

    fn new(inbound: TcpStream) -> Self;
    fn accept<'a>(self) -> Self::Accepting<'a>;
}

pub async fn user_endpoint_listener<Acceptor>(
    service_addr: SocketAddr,
    mut context: TrojanContext,
) -> Result<()>
where
    Acceptor: RequestFromClient + Send + 'static,
{
    let (shutdown_tx, shutdown) = broadcast::channel::<()>(1);
    let service_listener = TcpListener::bind(&service_addr).await?;

    #[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
    let tls_config = Arc::new(tls_client_config().await);

    #[cfg(feature = "quic")]
    let (task_tx, task_rx) = tokio::sync::mpsc::channel(20);
    #[cfg(feature = "quic")]
    tokio::spawn(quic_connection_daemon(
        context.clone_with_signal(shutdown),
        task_rx,
    ));

    loop {
        try_recv!(broadcast, context.shutdown);
        let (stream, _) = service_listener.accept().await?;
        debug!("accepted http: {:?}", stream);
        let incoming: _ = Acceptor::new(stream).accept();
        let new_context = context.clone_with_signal(shutdown_tx.subscribe());
        match &context.options.connection_mode {
            #[cfg(feature = "tcp_tls")]
            ConnectionMode::TcpTLS => {
                let connecting: _ = TrojanTcpTlsConnector::new(tls_config.clone(), false)
                    .connect(context.options.clone());
                tokio::spawn(
                    forward(new_context, incoming, connecting)
                        .map_err(|e| error!("[tcp-tls]forward failed: {:?}", e)),
                );
            }
            #[cfg(feature = "lite_tls")]
            ConnectionMode::LiteTLS => {
                let connecting: _ = TrojanTcpTlsConnector::new(tls_config.clone(), true)
                    .connect(context.options.clone());
                tokio::spawn(
                    forward(new_context, incoming, connecting)
                        .map_err(|e| error!("[lite]forward failed: {:?}", e)),
                );
            }
            #[cfg(feature = "quic")]
            ConnectionMode::Quic => {
                let (conn_ret_tx, conn_ret_rx) = oneshot::channel();
                or_continue!(task_tx.send(conn_ret_tx).await);
                tokio::spawn(forward(new_context, incoming, async move {
                    Ok(ClientServerConnection::Quic(conn_ret_rx.await??))
                }));
            }
        }
    }
    Ok(())
}

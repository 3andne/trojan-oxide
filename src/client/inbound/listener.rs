use super::ClientConnectionRequest;
use super::{HttpRequest, Socks5Request};
use crate::{
    args::TrojanContext,
    client::outbound::forward,
    or_continue, try_recv,
    utils::{ClientServerConnection, ConnectionMode, MixAddrType},
};

#[cfg(feature = "quic")]
use crate::client::outbound::quic::*;
#[cfg(feature = "tcp_tls")]
use crate::client::outbound::tcp_tls::*;
use anyhow::Result;
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{broadcast, oneshot},
};
use tracing::*;

pub type ClientRequestAcceptResult = Result<(ClientConnectionRequest, MixAddrType)>;

pub async fn user_endpoint_listener<F, Fut>(
    mut upper_shutdown: oneshot::Receiver<()>,
    service_addr: SocketAddr,
    context: TrojanContext,
    accept_client_request: F,
) -> Result<()>
where
    F: Fn(TcpStream) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ClientRequestAcceptResult> + Send + 'static,
{
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let service_listener = TcpListener::bind(&service_addr).await?;
    let hash = context.options.password_hash.clone();
    let remote_addr = context.remote_socket_addr;
    let domain_string = Arc::new(context.options.proxy_url.clone());

    #[cfg(feature = "tcp_tls")]
    let tls_config = Arc::new(tls_client_config().await);

    #[cfg(feature = "quic")]
    let (task_tx, task_rx) = tokio::sync::mpsc::channel(20);
    #[cfg(feature = "quic")]
    tokio::spawn(quic_connection_daemon(context.clone(), task_rx));

    loop {
        try_recv!(oneshot, upper_shutdown);
        let (stream, _) = service_listener.accept().await?;
        debug!("accepted http: {:?}", stream);
        let shutdown_rx = shutdown_tx.subscribe();
        let hash_copy = hash.clone();

        match &context.options.connection_mode {
            #[cfg(feature = "tcp_tls")]
            ConnectionMode::TcpTLS => {
                let tls_config_copy = tls_config.clone();
                let domain_string_copy = domain_string.clone();
                tokio::spawn(forward(
                    stream,
                    shutdown_rx,
                    hash_copy,
                    accept_client_request.clone(),
                    connect_through_tcp_tls(tls_config_copy, domain_string_copy, remote_addr),
                ));
            }
            #[cfg(feature = "quic")]
            ConnectionMode::Quic => {
                let (conn_ret_tx, conn_ret_rx) = oneshot::channel();
                or_continue!(task_tx.send(conn_ret_tx).await);
                tokio::spawn(forward(
                    stream,
                    shutdown_rx,
                    hash_copy,
                    accept_client_request.clone(),
                    async move { Ok(ClientServerConnection::Quic(conn_ret_rx.await??)) },
                ));
            }
        }
    }
    Ok(())
}

macro_rules! request_accept_helper {
    ($fn_name:ident, $request_type:ident) => {
        pub async fn $fn_name(stream: TcpStream) -> ClientRequestAcceptResult {
            let mut req = $request_type::new();
            let conn_req = req.accept(stream).await?;
            Ok((conn_req, req.addr()))
        }
    };
}

request_accept_helper!(accept_http_request, HttpRequest);
request_accept_helper!(accept_sock5_request, Socks5Request);

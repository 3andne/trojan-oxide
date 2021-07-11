use super::trojan_auth::{trojan_auth_tcp, trojan_auth_udp};

#[cfg(feature = "udp")]
use crate::utils::relay_udp;
use crate::{
    client::inbound::ClientRequestAcceptResult,
    utils::{relay_tcp, ClientServerConnection, ConnectionRequest},
};
use anyhow::Result;
use lazy_static::lazy_static;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{net::TcpStream, sync::broadcast};
use tracing::*;

lazy_static! {
    static ref CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
}

pub async fn forward<F, Fut, Connecting>(
    stream: TcpStream,
    upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    accept_client_request: F,
    connect_to_server: Connecting,
) -> Result<()>
where
    F: FnOnce(TcpStream) -> Fut + Send,
    Fut: Future<Output = ClientRequestAcceptResult> + Send,
    Connecting: Future<Output = Result<ClientServerConnection>> + Send,
{
    let (conn_req, addr) = accept_client_request(stream).await?;

    let mut outbound = connect_to_server.await.map_err(|e| {
        error!("forward error: {}", e);
        e
    })?;
    let conn_id = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);

    use ConnectionRequest::*;
    match conn_req {
        TCP(inbound) => {
            trojan_auth_tcp(&addr, &mut outbound, password_hash).await?;
            info!(
                "[tcp][{}]{:?} => {:?}",
                conn_id,
                inbound.peer_addr()?,
                &addr
            );
            relay_tcp(inbound, outbound, upper_shutdown).await;
            debug!("[end][tcp][{}]", conn_id);
        }
        #[cfg(feature = "udp")]
        UDP(inbound) => {
            trojan_auth_udp(&mut outbound, password_hash).await?;
            info!("[udp][{}] => {:?}", conn_id, &addr);
            relay_udp(inbound, outbound, upper_shutdown).await;
            info!("[end][udp][{}]", conn_id);
        }
        #[cfg(feature = "quic")]
        ECHO(_) => panic!("unreachable"),
        _ => panic!("functionality not included"),
    }

    Ok(())
}

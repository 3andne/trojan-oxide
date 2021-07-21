use super::trojan_auth::trojan_auth;

#[cfg(feature = "udp")]
use crate::utils::relay_udp;
use crate::{
    client::inbound::ClientRequestAcceptResult,
    protocol::ServiceMode,
    utils::{relay_tcp, ClientServerConnection, ConnectionRequest, MixAddrType},
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
    static ref TCP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
    static ref UDP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
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
        error!("forward error: {:#}", e);
        e
    })?;

    use ConnectionRequest::*;
    match conn_req {
        TCP(inbound) => {
            trojan_auth(ServiceMode::TCP, &addr, &mut outbound, password_hash).await?;
            let conn_id = TCP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
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
            let conn_id = UDP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            trojan_auth(
                ServiceMode::UDP,
                &MixAddrType::new_null(),
                &mut outbound,
                password_hash,
            )
            .await?;
            info!("[udp][{}] => {:?}", conn_id, &addr);
            relay_udp(inbound, outbound, upper_shutdown, conn_id).await;
            info!("[end][udp][{}]", conn_id);
        }
        MiniTLS(x) => {}
        #[cfg(feature = "quic")]
        ECHO(_) => panic!("unreachable"),
        #[allow(unreachable_patterns)]
        _ => panic!("functionality not included"),
    }

    Ok(())
}

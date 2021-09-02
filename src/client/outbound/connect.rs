use super::trojan_auth::trojan_auth;

#[cfg(feature = "quic")]
use crate::client::outbound::quic::send_echo;
#[cfg(feature = "udp")]
use crate::client::utils::relay_udp;

use crate::client::inbound::ClientRequestAcceptResult;
use crate::{
    args::TrojanContext,
    client::{
        outbound::request_cmd::ClientRequestCMD,
        utils::{relay_tcp, ClientServerConnection},
    },
    utils::ConnectionRequest,
};
use anyhow::Result;
use std::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
};
use tracing::*;

static TCP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
static UDP_CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub async fn forward<Incomming, Connecting>(
    context: TrojanContext,
    incomming: Incomming,
    connecting: Connecting,
) -> Result<()>
where
    Incomming: Future<Output = ClientRequestAcceptResult> + Send,
    Connecting: Future<Output = Result<ClientServerConnection>> + Send,
{
    let (conn_req, addr) = incomming.await.map_err(|e| {
        error!("forward error: {:#}", e);
        e
    })?;

    let mut outbound = connecting.await.map_err(|e| {
        error!("forward error: {:#}", e);
        e
    })?;

    let opt = &*context.options;
    let connection_cmd = ClientRequestCMD(&conn_req, &outbound).get_cmd();
    trojan_auth(connection_cmd, &addr, &mut outbound, &opt.password_hash).await?;

    use ConnectionRequest::*;
    match conn_req {
        TCP(inbound) => {
            let conn_id = TCP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            relay_tcp(inbound, outbound, context.shutdown, conn_id, &addr).await?;
        }
        #[cfg(feature = "udp")]
        UDP(inbound) => {
            let conn_id = UDP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
            info!("[udp][{}] => {:?}", conn_id, &addr);
            relay_udp(inbound, outbound, context.shutdown, conn_id).await?;
            info!("[end][udp][{}]", conn_id);
        }
        #[cfg(feature = "quic")]
        ECHO(echo_rx) => match outbound {
            ClientServerConnection::Quic(outbound) => {
                send_echo(outbound, echo_rx).await;
            }
            _ => unreachable!(),
        },
        _PHANTOM(_) => unreachable!(),
        #[allow(unreachable_patterns)]
        _ => panic!("functionality not included"),
    }

    Ok(())
}

use std::{sync::atomic::Ordering, time::Duration};

use crate::{
    server::{outbound::connector::TCP_CONNECTION_COUNTER, Splitable},
    utils::{copy_tcp, MixAddrType, TimeoutMonitor},
};
use anyhow::{anyhow, Context, Error, Result};
use tokio::{net::TcpStream, select, sync::broadcast};
use tracing::info;

pub(crate) async fn outbound_connect(target_host: &MixAddrType) -> Result<TcpStream> {
    let outbound = if target_host.is_ip() {
        TcpStream::connect(target_host.to_socket_addrs()).await
    } else {
        TcpStream::connect(target_host.host_repr()).await
    }
    .map_err(|e| Error::new(e))
    .with_context(|| anyhow!("failed to connect to {:?}", target_host))?;

    outbound
        .set_nodelay(true)
        .map_err(|e| Error::new(e))
        .with_context(|| {
            anyhow!(
                "failed to set tcp_nodelay for outbound stream {:?}",
                target_host
            )
        })?;
    Ok(outbound)
}

pub(crate) async fn relay_tcp<I: Splitable>(
    inbound: I,
    outbound: TcpStream,
    target_host: &MixAddrType,
    mut upper_shutdown: broadcast::Receiver<()>,
) {
    let (mut in_read, mut in_write) = inbound.split();
    let (out_read, out_write) = outbound.split();
    let timeout_monitor = TimeoutMonitor::new(Duration::from_secs(5 * 60));
    let mut out_read = timeout_monitor.watch(out_read);
    let mut out_write = timeout_monitor.watch(out_write);
    let conn_id = TCP_CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);

    info!("[tcp][{}] => {:?}", conn_id, target_host);
    // FUUUUUCK YOU tokio::io::copy, you buggy little shit.
    select! {
        _ = copy_tcp(&mut out_read, &mut in_write) => {
            info!("[tcp][{}]end downloading", conn_id);
        },
        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
            info!("[tcp][{}]end uploading", conn_id);
        },
        _ = timeout_monitor => {
            info!("[tcp][{}]end timeout", conn_id);
        }
        _ = upper_shutdown.recv() => {
            info!("[tcp][{}]shutdown signal received", conn_id);
        },
    }
}

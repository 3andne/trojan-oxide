use super::{ClientServerConnection, ClientTcpStream};
#[cfg(feature = "udp")]
use {
    super::Socks5UdpStream,
    crate::utils::{copy_udp, new_trojan_udp_stream},
};

use crate::{
    adapt,
    utils::{Adapter, MixAddrType, ParserError, Splitable, WRTuple},
};
use anyhow::{anyhow, Context, Result};
use tokio::{select, sync::broadcast};
use tracing::{debug, info};

#[cfg(feature = "lite_tls")]
use crate::utils::lite_tls::LiteTlsStream;

pub async fn relay_tcp(
    inbound: ClientTcpStream,
    outbound: ClientServerConnection,
    shutdown: broadcast::Receiver<()>,
    conn_id: usize,
    target_host: &MixAddrType,
) -> Result<()> {
    match outbound {
        #[cfg(feature = "quic")]
        ClientServerConnection::Quic(outbound) => {
            let outbound = WRTuple::from_wr_tuple(outbound);
            adapt!(["tcp"][conn_id]
                inbound[Tcp] <=> outbound[Tcp] <=> target_host
                Until shutdown
            );
        }
        #[cfg(feature = "tcp_tls")]
        ClientServerConnection::TcpTLS(outbound) => {
            adapt!(["tcp"][conn_id]
                inbound[Tcp] <=> outbound[Tls] <=> target_host
                Until shutdown
            );
        }
        #[cfg(feature = "lite_tls")]
        ClientServerConnection::LiteTLS(mut outbound) => {
            let mut lite_tls_endpoint = LiteTlsStream::new_client_endpoint();
            let mut inbound = WRTuple::from_rw_tuple(inbound.split());
            match lite_tls_endpoint
                .handshake(&mut outbound, &mut inbound)
                .await
            {
                Ok(_) => {
                    info!("lite tls handshake succeed");
                    let (mut outbound, _) = outbound.into_inner();
                    lite_tls_endpoint.flush(&mut outbound, &mut inbound).await?;
                    adapt!(["lite"][conn_id]
                        inbound[Tcp] <=> outbound[Tcp] <=> target_host
                        Until shutdown
                    );
                }
                Err(e) => {
                    if let Some(e @ ParserError::Invalid(_)) = e.downcast_ref::<ParserError>() {
                        info!("not tls stream: {:#}", e);
                        lite_tls_endpoint.flush(&mut outbound, &mut inbound).await?;
                        adapt!(["lite"][conn_id]
                            inbound[Tcp] <=> outbound[Tls] <=> target_host
                            Until shutdown
                        );
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "udp")]
pub async fn relay_udp(
    mut inbound: Socks5UdpStream,
    outbound: ClientServerConnection,
    mut upper_shutdown: broadcast::Receiver<()>,
    conn_id: usize,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let (mut in_write, mut in_read) = inbound.split();
    match outbound {
        #[cfg(feature = "quic")]
        ClientServerConnection::Quic(quic_stream) => {
            let (mut out_write, mut out_read) = new_trojan_udp_stream(quic_stream, None).split();
            select! {
                res = copy_udp(&mut out_read, &mut in_write, None) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = copy_udp(&mut in_read, &mut out_write, Some(conn_id)) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
            in_write
                .shutdown()
                .await
                .with_context(|| anyhow!("failed to shutdown quic udp inbound"))?;
            out_write
                .shutdown()
                .await
                .with_context(|| anyhow!("failed to shutdown quic udp outbound"))?;
        }
        #[cfg(feature = "tcp_tls")]
        ClientServerConnection::TcpTLS(out_tls) => {
            let (mut out_write, mut out_read) = new_trojan_udp_stream(out_tls, None).split();
            select! {
                res = copy_udp(&mut out_read, &mut in_write, None) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = copy_udp(&mut in_read, &mut out_write, Some(conn_id)) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
            in_write
                .shutdown()
                .await
                .with_context(|| anyhow!("failed to shutdown tcp_tls udp inbound"))?;
            out_write
                .shutdown()
                .await
                .with_context(|| anyhow!("failed to shutdown tcp_tls udp outbound"))?;
        }
        #[cfg(feature = "lite_tls")]
        ClientServerConnection::LiteTLS(out_tls) => {
            let (mut out_write, mut out_read) = new_trojan_udp_stream(out_tls, None).split();
            select! {
                res = copy_udp(&mut out_read, &mut in_write, None) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = copy_udp(&mut in_read, &mut out_write, Some(conn_id)) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
            in_write
                .shutdown()
                .await
                .with_context(|| anyhow!("failed to shutdown lite_tls udp inbound"))?;
            out_write
                .shutdown()
                .await
                .with_context(|| anyhow!("failed to shutdown lite_tls udp outbound"))?;
        }
    }
    Ok(())
}

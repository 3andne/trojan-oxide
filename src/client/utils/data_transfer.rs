use super::{ClientServerConnection, ClientTcpStream};
#[cfg(feature = "udp")]
use {super::Socks5UdpStream, crate::utils::new_trojan_udp_stream};

use crate::{
    adapt,
    utils::{Adapter, MixAddrType, ParserError, Splitable, WRTuple},
};
use anyhow::{anyhow, Context, Result};
use tokio::sync::broadcast;
use tracing::info;

#[cfg(feature = "lite_tls")]
use crate::utils::lite_tls::LiteTlsStream;

pub async fn relay_tcp(
    mut inbound: ClientTcpStream,
    outbound: ClientServerConnection,
    shutdown: broadcast::Receiver<()>,
    conn_id: usize,
    target_host: &MixAddrType,
) -> Result<()> {
    match outbound {
        #[cfg(feature = "quic")]
        ClientServerConnection::Quic(outbound) => {
            let outbound = WRTuple::from_wr_tuple(outbound);
            adapt!([tcp][conn_id]
                inbound <=> outbound <=> target_host
                Until shutdown
            );
        }
        #[cfg(feature = "tcp_tls")]
        ClientServerConnection::TcpTLS(outbound) => {
            adapt!([tcp][conn_id]
                inbound <=> outbound <=> target_host
                Until shutdown
            );
        }
        #[cfg(feature = "lite_tls")]
        ClientServerConnection::LiteTLS(mut outbound) => {
            let mut lite_tls_endpoint = LiteTlsStream::new_client_endpoint();
            let mut inbound_tmp = WRTuple::from_rw_tuple(inbound.split());

            // there is a potential bug here, if timeout is too short for a
            // valid handshake, it closes unexpectedly and immediately try for
            // another time. However for the second time, it is not recognised
            // as a tls stream and therefore fails again.
            // I set a reasonably large timeout here to avoid such problem,
            // but the reason for the failed second round is currently unknown.
            match lite_tls_endpoint
                .handshake_timeout(&mut outbound, &mut inbound_tmp)
                .await
            {
                Ok(_) => {
                    let ver = lite_tls_endpoint.version;
                    if ver.is_none() {
                        return Ok(());
                    }
                    info!("[{}]lite tls handshake succeed", ver.unwrap());
                    let (mut outbound, _) = outbound.into_inner();
                    let mut inbound = inbound.inner;

                    lite_tls_endpoint
                        .flush_tls(&mut inbound, &mut outbound)
                        .await?;

                    adapt!([lite][conn_id]
                        inbound <=> outbound <=> target_host
                        Until shutdown
                    );
                }
                Err(e) => {
                    if let Some(e @ ParserError::Invalid(_)) = e.downcast_ref::<ParserError>() {
                        info!("not tls stream: {:#}", e);
                        lite_tls_endpoint
                            .flush_non_tls(&mut outbound, &mut inbound_tmp)
                            .await?;
                        adapt!([lite][conn_id]
                            inbound <=> outbound <=> target_host
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
    upper_shutdown: broadcast::Receiver<()>,
    conn_id: usize,
) -> Result<()> {
    match outbound {
        #[cfg(feature = "quic")]
        ClientServerConnection::Quic(out_quic) => {
            let outbound = new_trojan_udp_stream(out_quic, None);
            adapt!([udp][conn_id]inbound <=> outbound
                Until upper_shutdown
            );
        }
        #[cfg(feature = "tcp_tls")]
        ClientServerConnection::TcpTLS(out_tls) => {
            let outbound = new_trojan_udp_stream(out_tls, None);
            adapt!([udp][conn_id]inbound <=> outbound
                Until upper_shutdown
            );
        }
        #[cfg(feature = "lite_tls")]
        ClientServerConnection::LiteTLS(out_tls) => {
            let outbound = new_trojan_udp_stream(out_tls, None);
            adapt!([udp][conn_id]inbound <=> outbound
                Until upper_shutdown
            );
        }
    }
    Ok(())
}

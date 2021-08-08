use super::{ClientServerConnection, ClientTcpStream};
#[cfg(feature = "udp")]
use {super::Socks5UdpStream, crate::utils::new_trojan_udp_stream};

use crate::{
    adapt,
    utils::{Adapter, MixAddrType, CommonParserError, Splitable, WRTuple},
};
use anyhow::{anyhow, Context, Result};
use tokio::{
    sync::broadcast,
    time::{timeout, Duration},
};
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
                inbound[Tcp] <=> outbound[Tcp] <=> target_host
                Until shutdown
            );
        }
        #[cfg(feature = "tcp_tls")]
        ClientServerConnection::TcpTLS(outbound) => {
            adapt!([tcp][conn_id]
                inbound[Tcp] <=> outbound[Tls] <=> target_host
                Until shutdown
            );
        }
        #[cfg(feature = "lite_tls")]
        ClientServerConnection::LiteTLS(mut outbound) => {
            let mut lite_tls_endpoint = LiteTlsStream::new_client_endpoint();
            let mut inbound_tmp = WRTuple::from_rw_tuple(inbound.split());
            match timeout(
                Duration::from_secs(5),
                lite_tls_endpoint.handshake(&mut outbound, &mut inbound_tmp),
            )
            .await?
            {
                Ok(_) => {
                    info!("lite tls handshake succeed");
                    let (mut outbound, _) = outbound.into_inner();
                    // outbound.
                    lite_tls_endpoint
                        .flush(&mut outbound, &mut inbound_tmp)
                        .await?;
                    adapt!([lite][conn_id]
                        inbound[Tcp] <=> outbound[Tcp] <=> target_host
                        Until shutdown
                    );
                }
                Err(e) => {
                    if let Some(e @ CommonParserError::Invalid(_)) = e.downcast_ref::<CommonParserError>() {
                        info!("not tls stream: {:#}", e);
                        lite_tls_endpoint
                            .flush(&mut outbound, &mut inbound_tmp)
                            .await?;
                        adapt!([lite][conn_id]
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

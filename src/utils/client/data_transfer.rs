#[cfg(feature = "udp")]
use crate::utils::{copy_udp, new_trojan_udp_stream, Socks5UdpStream};
use crate::utils::{ClientServerConnection, ClientTcpStream, ParserError, WRTuple};
use tokio::{select, sync::broadcast};
use tracing::{debug, error};
#[cfg(feature = "tcp_tls")]
use {crate::utils::copy_tcp, tokio::io::split};

#[cfg(feature = "tcp_tls")]
use crate::utils::lite_tls::LiteTlsStream;

pub async fn relay_tcp(
    mut inbound: ClientTcpStream,
    outbound: ClientServerConnection,
    mut upper_shutdown: broadcast::Receiver<()>,
) {
    let (mut in_read, mut in_write) = inbound.split();
    match outbound {
        #[cfg(feature = "quic")]
        ClientServerConnection::Quic((mut out_write, mut out_read)) => {
            select! {
                res = tokio::io::copy(&mut out_read, &mut in_write) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = tokio::io::copy(&mut in_read, &mut out_write) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
        }
        #[cfg(feature = "tcp_tls")]
        ClientServerConnection::TcpTLS(out_tls) => {
            let (mut out_read, mut out_write) = split(out_tls);
            select! {
                res = tokio::io::copy(&mut out_read, &mut in_write) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = copy_tcp(&mut in_read, &mut out_write) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
        }
        #[cfg(feature = "lite_tls")]
        ClientServerConnection::LiteTLS(mut outbound) => {
            let mut lite_tls_endpoint = LiteTlsStream::new_client_endpoint();
            let mut inbound = WRTuple((in_write, in_read));
            match lite_tls_endpoint
                .handshake(&mut outbound, &mut inbound)
                .await
            {
                Ok(_) => {
                    let (mut outbound, _) = outbound.into_inner();
                    if let Err(e) = lite_tls_endpoint.flush(&mut outbound, &mut inbound).await {
                        error!("flushing failed, {:#}", e);
                        return;
                    }

                    let (mut out_read, mut out_write) = outbound.split();
                    let WRTuple((mut in_write, mut in_read)) = inbound;
                    select! {
                        res = tokio::io::copy(&mut out_read, &mut in_write) => {
                            debug!("tcp relaying download end, {:?}", res);
                        },
                        res = tokio::io::copy(&mut in_read, &mut out_write) => {
                            debug!("tcp relaying upload end, {:?}", res);
                        },
                        _ = upper_shutdown.recv() => {
                            debug!("shutdown signal received");
                        },
                    }
                }
                Err(e) => {
                    if let Some(&ParserError::Invalid(x)) = e.downcast_ref::<ParserError>() {
                        debug!("not tls stream: {}", x);
                        if let Err(e) = lite_tls_endpoint.flush(&mut outbound, &mut inbound).await {
                            error!("tcp relaying download end, {:#}", e);
                            return;
                        }

                        let (mut out_read, mut out_write) = split(outbound);
                        let WRTuple((mut in_write, mut in_read)) = inbound;
                        select! {
                            res = tokio::io::copy(&mut out_read, &mut in_write) => {
                                debug!("tcp relaying download end, {:?}", res);
                            },
                            res = copy_tcp(&mut in_read, &mut out_write) => {
                                debug!("tcp relaying upload end, {:?}", res);
                            },
                            _ = upper_shutdown.recv() => {
                                debug!("shutdown signal received");
                            },
                        }
                    } else {
                        error!("lite tls hadnshake error: {:#}", e);
                    }
                }
            };
        }
    }
}

#[cfg(feature = "udp")]
pub async fn relay_udp(
    mut inbound: Socks5UdpStream,
    outbound: ClientServerConnection,
    mut upper_shutdown: broadcast::Receiver<()>,
    conn_id: usize,
) {
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
        }
        #[cfg(feature = "tcp_tls")]
        ClientServerConnection::TcpTLS(out_tls) => {
            // let (out_read, out_write) = split(out_tls);
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
        }
        #[cfg(feature = "lite_tls")]
        ClientServerConnection::LiteTLS(_) => {
            unimplemented!("udp in minitls should be treated as tcp_tls")
        }
    }
}

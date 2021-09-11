use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::broadcast,
};
use tracing::{debug, info};

use crate::{
    adapt,
    protocol::TCP_MAX_IDLE_TIMEOUT,
    utils::{
        lite_tls::{LeaveTls, LiteTlsStream},
        Adapter, BufferedRecv, MixAddrType, ParserError,
    },
};
use anyhow::{anyhow, Context, Result};

pub enum TcpOption<I> {
    TLS(I),
    LiteTLS(I),
}

impl<I> TcpOption<BufferedRecv<I>>
where
    I: AsyncRead + AsyncWrite + LeaveTls + Unpin,
{
    pub async fn forward(
        self,
        mut outbound: TcpStream,
        target_host: &MixAddrType,
        shutdown: broadcast::Receiver<()>,
        conn_id: usize,
    ) -> Result<()> {
        use TcpOption::*;
        match self {
            TLS(inbound) => {
                adapt!([tcp][conn_id]
                    inbound <=> outbound <=> target_host
                    Until shutdown Or Sec TCP_MAX_IDLE_TIMEOUT
                );
            }
            LiteTLS(mut inbound) => {
                let mut lite_tls_endpoint = LiteTlsStream::new_server_endpoint();
                match lite_tls_endpoint
                    .handshake_timeout(&mut outbound, &mut inbound)
                    .await
                {
                    Ok(_) => {
                        let ver = lite_tls_endpoint.version;
                        if ver.is_none() {
                            // EOF
                            return Ok(());
                        }
                        info!("[{}]lite tls handshake succeed", ver.unwrap());
                        let mut inbound = inbound.into_inner().0.leave();
                        lite_tls_endpoint
                            .flush_tls(&mut outbound, &mut inbound)
                            .await?;
                        debug!("lite tls start relaying");
                        adapt!([lite][conn_id]
                            inbound <=> outbound <=> target_host
                            Until shutdown Or Sec TCP_MAX_IDLE_TIMEOUT
                        );
                    }
                    Err(e) => {
                        if let Some(ParserError::Invalid(x)) = e.downcast_ref::<ParserError>() {
                            debug!("not tls stream: {}", x);
                            lite_tls_endpoint
                                .flush_non_tls(&mut outbound, &mut inbound)
                                .await?;
                            adapt!([tcp][conn_id]
                                inbound <=> outbound <=> target_host
                                Until shutdown Or Sec TCP_MAX_IDLE_TIMEOUT
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::broadcast,
};
use tracing::{debug, info};

use crate::{
    adapt,
    utils::{
        lite_tls::{LeaveTls, LiteTlsStream},
        Adapter, BufferedRecv, MixAddrType, ParserError, Splitable,
    },
    protocol::TCP_MAX_IDLE_TIMEOUT
};
use anyhow::Result;

pub enum TcpOption<I> {
    TLS(I),
    LiteTLS(I),
}

impl<I> TcpOption<BufferedRecv<I>>
where
    I: AsyncRead + AsyncWrite + Splitable + LeaveTls + Unpin,
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
                adapt!(["tcp"][conn_id]
                    inbound[Tls] <=> outbound[Tcp] <=> target_host
                    Until shutdown Or Sec TCP_MAX_IDLE_TIMEOUT
                );
            }
            LiteTLS(mut inbound) => {
                let mut lite_tls_endpoint = LiteTlsStream::new_server_endpoint();
                match lite_tls_endpoint
                    .handshake(&mut outbound, &mut inbound)
                    .await
                {
                    Ok(_) => {
                        lite_tls_endpoint.flush(&mut outbound, &mut inbound).await?;
                        let inbound = inbound.into_inner().leave();
                        debug!("lite tls start relaying");
                        adapt!(["lite"][conn_id]
                            inbound[Tcp] <=> outbound[Tcp] <=> target_host
                            Until shutdown Or Sec TCP_MAX_IDLE_TIMEOUT
                        );
                    }
                    Err(e) => {
                        if let Some(ParserError::Invalid(x)) = e.downcast_ref::<ParserError>() {
                            debug!("not tls stream: {}", x);
                            lite_tls_endpoint.flush(&mut outbound, &mut inbound).await?;
                            adapt!(["tcp"][conn_id]
                                inbound[Tls] <=> outbound[Tcp] <=> target_host
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

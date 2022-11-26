use crate::{
    args::Opt,
    client::utils::{get_rustls_config, ClientServerConnection},
};
use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore, ServerName},
    TlsConnector,
};

pub async fn tls_client_config() -> ClientConfig {
    get_rustls_config(RootCertStore::empty())
}

pub struct TrojanTcpTlsConnector {
    tls_config: Arc<ClientConfig>,
    is_lite: bool,
}

impl TrojanTcpTlsConnector {
    pub fn new(tls_config: Arc<ClientConfig>, is_lite: bool) -> Self {
        Self {
            tls_config,
            is_lite,
        }
    }

    pub async fn connect(self, opt: Arc<Opt>) -> Result<ClientServerConnection> {
        let Self {
            tls_config,
            is_lite,
        } = self;
        let opt = &*opt;
        let connector = TlsConnector::from(tls_config);
        let stream = TcpStream::connect(&opt.remote_socket_addr.unwrap()).await?;
        stream.set_nodelay(true)?;
        let stream = connector
            .connect(
                ServerName::try_from(opt.server_hostname.as_str()).expect("invalid DNS name"),
                stream,
            )
            .await?;
        use ClientServerConnection::*;
        return Ok(match is_lite {
            #[cfg(feature = "lite_tls")]
            true => LiteTLS(stream),
            #[cfg(feature = "tcp_tls")]
            false => TcpTLS(stream),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        });
    }
}

use crate::{args::Opt, client::utils::ClientServerConnection};
use anyhow::{anyhow, Result};
use rustls_native_certs;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::ClientConfig, rustls::ClientSessionMemoryCache, webpki::DNSNameRef, TlsConnector,
};

pub async fn tls_client_config() -> ClientConfig {
    let mut config = ClientConfig::new();
    // config
    //     .root_store
    //     .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.root_store =
        rustls_native_certs::load_native_certs().expect("could not load platform certs");
    config.set_persistence(ClientSessionMemoryCache::new(128));
    config
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
        let domain = DNSNameRef::try_from_ascii_str(&opt.server_hostname)
            .map_err(|_| anyhow!("invalid dnsname"))?;
        let connector = TlsConnector::from(tls_config);
        let stream = TcpStream::connect(&opt.remote_socket_addr.unwrap()).await?;
        stream.set_nodelay(true)?;
        let stream = connector.connect(domain, stream).await?;
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

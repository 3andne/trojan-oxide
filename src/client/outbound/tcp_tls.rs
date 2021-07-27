use crate::utils::ClientServerConnection;
use anyhow::{anyhow, Result};
use rustls_native_certs;
use std::net::SocketAddr;
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

pub async fn connect_through_tcp_tls(
    config: Arc<ClientConfig>,
    domain_string: Arc<String>,
    remote_addr: SocketAddr,
    lite_tls: bool,
) -> Result<ClientServerConnection> {
    let domain =
        DNSNameRef::try_from_ascii_str(&domain_string).map_err(|_| anyhow!("invalid dnsname"))?;
    let connector = TlsConnector::from(config);
    let stream = TcpStream::connect(remote_addr).await?;
    stream.set_nodelay(true)?;
    let stream = connector.connect(domain, stream).await?;
    use ClientServerConnection::*;
    return Ok(if lite_tls {
        LiteTLS(stream)
    } else {
        TcpTLS(stream)
    });
}

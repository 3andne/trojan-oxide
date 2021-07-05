use crate::args::Opt;
use crate::utils::ClientServerConnection;
use anyhow::{anyhow, Result};
use rustls_native_certs;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::ClientConfig, rustls::ClientSessionMemoryCache, webpki::DNSNameRef, TlsConnector,
};

use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig, Ticketer};

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
) -> Result<ClientServerConnection> {
    let domain =
        DNSNameRef::try_from_ascii_str(&domain_string).map_err(|_| anyhow!("invalid dnsname"))?;
    let connector = TlsConnector::from(config);
    let stream = TcpStream::connect(remote_addr).await?;
    let stream = connector.connect(domain, stream).await?;
    return Ok(ClientServerConnection::TcpTLS(stream));
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

pub async fn tls_server_config(options: &Opt) -> Result<ServerConfig> {
    let mut config = ServerConfig::new(NoClientAuth::new());

    let certs = load_certs(options.cert.as_ref().unwrap())?;
    let mut keys = load_keys(options.key.as_ref().unwrap())?;
    config
        .set_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    config.ticketer = Ticketer::new();
    Ok(config)
}

use super::get_server_local_addr;
use crate::{
    args::Opt,
    protocol::{ALPN_QUIC_HTTP, MAX_CONCURRENT_BIDI_STREAMS, QUIC_MAX_IDLE_TIMEOUT},
};
use anyhow::*;
#[cfg(feature = "quic")]
use quinn::*;
use std::sync::Arc;
use tokio::{fs, io};
use tracing::*;

#[derive(Debug)]
pub struct QuicStream(pub(super) SendStream, pub(super) RecvStream );


pub async fn quic_tunnel_rx(options: &Opt) -> Result<(Endpoint, Incoming)> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(QUIC_MAX_IDLE_TIMEOUT))?;
    transport_config.persistent_congestion_threshold(6);
    transport_config.packet_threshold(4);
    transport_config.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS as u64)?;

    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(ALPN_QUIC_HTTP);

    // server_config.use_stateless_retry(true);
    if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        debug!("private key path {:?}, cert_path {:?}", key_path, cert_path);
        let key = fs::read(key_path)
            .await
            .context("failed to read private key")?;
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            quinn::PrivateKey::from_der(&key)?
        } else {
            quinn::PrivateKey::from_pem(&key)?
        };
        let cert_chain = fs::read(cert_path)
            .await
            .context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            quinn::CertificateChain::from_certs(Some(
                quinn::Certificate::from_der(&cert_chain).unwrap(),
            ))
        } else {
            quinn::CertificateChain::from_pem(&cert_chain)?
        };
        server_config.certificate(cert_chain, key)?;
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let cert = fs::read(&cert_path).await;
        let key = fs::read(&key_path).await;
        let (cert, key) = match cert.and_then(|x| Ok((x, key?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der().unwrap();
                fs::create_dir_all(&path)
                    .await
                    .context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert)
                    .await
                    .context("failed to write certificate")?;
                fs::write(&key_path, &key)
                    .await
                    .context("failed to write private key")?;
                (cert, key)
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert = quinn::Certificate::from_der(&cert)?;
        server_config.certificate(quinn::CertificateChain::from_certs(vec![cert]), key)?;
    }

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let server_addr = get_server_local_addr(options);
    Ok(endpoint.bind(&server_addr)?)
}

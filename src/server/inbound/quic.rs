use super::get_server_local_addr;
use crate::{
    args::Opt,
    protocol::{ALPN_QUIC_HTTP, MAX_CONCURRENT_BIDI_STREAMS, QUIC_MAX_IDLE_TIMEOUT},
    server::utils::get_server_certs_and_key,
};
use anyhow::{bail, Context, Result};
use quinn::Endpoint;
#[cfg(feature = "quic")]
use quinn::*;
use std::sync::Arc;
use tokio::{fs, io};
use tokio_rustls::rustls::{self, ServerConfig};
use tracing::*;

pub async fn quic_tunnel_rx(options: &Opt) -> Result<(Endpoint, Incoming)> {
    let (certs, key) = if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        get_server_certs_and_key(key_path, cert_path).await?
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

        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };

    let mut crypto_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    crypto_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto_config));

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_idle_timeout(Some(QUIC_MAX_IDLE_TIMEOUT.try_into()?));
    transport_config.persistent_congestion_threshold(6);
    transport_config.packet_threshold(4);
    transport_config.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.try_into()?);

    let server_addr = get_server_local_addr(options.server_port);
    Ok(Endpoint::server(server_config, server_addr)?)
}

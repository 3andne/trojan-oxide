use crate::args::Opt;
use crate::server::utils::get_server_certs_and_key;
use anyhow::Result;
use std::io;

use tokio_rustls::rustls::{ServerConfig, Ticketer};

pub async fn tls_server_config(options: &Opt) -> Result<ServerConfig> {
    let (cert, key) = get_server_certs_and_key(
        options.key.as_ref().unwrap(),
        options.cert.as_ref().unwrap(),
    )
    .await?;
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    config.ticketer = Ticketer::new()?;
    Ok(config)
}

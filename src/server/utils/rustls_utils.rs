use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::fs;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};

pub async fn get_server_certs_and_key(
    key_path: &PathBuf,
    cert_path: &PathBuf,
) -> Result<(Vec<Certificate>, PrivateKey)> {
    let key = fs::read(key_path)
        .await
        .context("failed to read private key")?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        rustls::PrivateKey(key)
    } else {
        let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
            .context("malformed PKCS #8 private key")?;
        match pkcs8.into_iter().next() {
            Some(x) => rustls::PrivateKey(x),
            None => {
                let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                    .context("malformed PKCS #1 private key")?;
                match rsa.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        anyhow::bail!("no private keys found");
                    }
                }
            }
        }
    };
    let cert_chain = fs::read(cert_path)
        .await
        .context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        vec![rustls::Certificate(cert_chain)]
    } else {
        rustls_pemfile::certs(&mut &*cert_chain)
            .context("invalid PEM-encoded certificate")?
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    Ok((cert_chain, key))
}

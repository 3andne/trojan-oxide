use crate::args::Opt;
use anyhow::Result;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use tokio_rustls::rustls::ciphersuite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig, Ticketer};

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
    config.ciphersuites = vec![
        &TLS13_AES_128_GCM_SHA256,
        &TLS13_AES_256_GCM_SHA384,
        &TLS13_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    let certs = load_certs(options.cert.as_ref().unwrap())?;
    let mut keys = load_keys(options.key.as_ref().unwrap())?;
    config
        .set_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    config.ticketer = Ticketer::new();
    Ok(config)
}

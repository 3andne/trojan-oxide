use tokio_rustls::rustls::{Certificate, ClientConfig, RootCertStore};

pub fn get_rustls_config(mut roots: RootCertStore) -> ClientConfig {
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(&Certificate(cert.0)).unwrap();
    }

    ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

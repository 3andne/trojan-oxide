use crate::args::Opt;
use anyhow::*;
use quinn::*;
use std::net::ToSocketAddrs;
use tokio::{fs, io};
use tracing::*;
use url::Url;

// #[allow(dead_code)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

async fn load_cert(options: &Opt, client_config: &mut ClientConfigBuilder) -> Result<()> {
    if let Some(ca_path) = &options.ca {
        client_config
            .add_certificate_authority(quinn::Certificate::from_der(&fs::read(&ca_path).await?)?)?;
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")).await {
            Ok(cert) => {
                client_config.add_certificate_authority(quinn::Certificate::from_der(&cert)?)?;
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    info!("local server certificate not found");
                } else {
                    error!("failed to open local server certificate: {}", e);
                }
                return Err(anyhow::Error::new(e));
            }
        }
    }
    Ok(())
}

async fn quic_tunnel_tx(options: &Opt) -> Result<Connection> {
    let url = Url::parse(options.remote_url.as_str())?;
    let remote = (url.host_str().unwrap(), url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(ALPN_QUIC_HTTP);

    load_cert(options, &mut client_config).await?;

    endpoint.default_client_config(client_config.build());

    let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;

    let host = options.remote_url.as_str();

    eprintln!("connecting to {} at {}", host, remote);
    let new_conn = endpoint
        .connect(&remote, &host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;

    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;
    Ok(conn)
}

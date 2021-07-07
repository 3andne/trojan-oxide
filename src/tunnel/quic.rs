use crate::{args::{Opt, TrojanContext}, tunnel::get_server_local_addr};
use anyhow::*;
use lazy_static::lazy_static;
use quinn::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use std::{net::SocketAddr, sync::atomic::Ordering::SeqCst};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tokio::time::timeout;
use tokio::{fs, io};
use tracing::*;
use webpki_roots;

#[allow(dead_code)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const ECHO_PHRASE: &str = "echo";
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_CONCURRENT_BIDI_STREAMS: usize = 30;

lazy_static! {
    static ref IS_CONNECTION_OPENED: AtomicBool = AtomicBool::new(false);
}

#[derive(Default)]
struct QuicConnectionWrapper {
    connection: Option<Connection>,
    concurrent_streams_counter: usize,
}

impl QuicConnectionWrapper {
    pub fn refresh(&mut self, conn: Connection) {
        self.connection = Some(conn);
        self.concurrent_streams_counter = 0;
    }

    pub fn open_bi(&mut self) -> Option<OpenBi> {
        if self.has_remaining() {
            self.concurrent_streams_counter += 1;
            Some(self.connection.as_ref().unwrap().open_bi())
        } else {
            None
        }
    }

    pub fn has_remaining(&self) -> bool {
        self.concurrent_streams_counter < MAX_CONCURRENT_BIDI_STREAMS
    }
}

async fn new_echo_task(echo_stream: (SendStream, RecvStream), mut echo_rx: mpsc::Receiver<()>) {
    let (mut write, mut read) = echo_stream;

    let mut buf = [0u8; ECHO_PHRASE.len()];
    loop {
        let _ = echo_rx.recv().await;
        match timeout(
            Duration::from_secs(2),
            write.write_all(ECHO_PHRASE.as_bytes()),
        )
        .await
        {
            Ok(Ok(_)) => {
                debug!("echo written");
            }
            other => {
                info!(
                    "[echo][send] connection reset detected: {:?}, buf {:?}",
                    other, buf
                );
                IS_CONNECTION_OPENED.store(false, SeqCst);
                echo_rx.close();
                return;
            }
        }

        match timeout(Duration::from_secs(2), read.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {
                debug!("echo received");
            }
            other => {
                info!(
                    "[echo][recv] connection reset detected: {:?}, buf {:?}",
                    other, buf
                );
                IS_CONNECTION_OPENED.store(false, SeqCst);
                echo_rx.close();
                return;
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}

pub struct EndpointManager {
    inner: Endpoint,
    connection: QuicConnectionWrapper,
    remote: SocketAddr,
    remote_url: String,
    password: Arc<String>,
    echo_tx: Option<mpsc::Sender<()>>,
}

impl EndpointManager {
    pub async fn new(context: &TrojanContext) -> Result<Self> {
        let (inner, _) = new_builder(&context.options)
            .await?
            .bind(&"[::]:0".parse().unwrap())?;
        let remote = context.remote_socket_addr;
        let remote_url = context.options.proxy_url.clone();

        let password = context.options.password_hash.clone();

        let mut _self = Self {
            inner,
            connection: QuicConnectionWrapper::default(),
            remote,
            remote_url,
            password,
            echo_tx: None,
        };

        _self.new_connection().await?;

        Ok(_self)
    }

    fn echo_task_status(&self) -> bool {
        match self.echo_tx {
            Some(ref tx) => {
                if tx.is_closed() {
                    false
                } else {
                    true
                }
            }
            None => false,
        }
    }

    async fn echo(&mut self) -> Result<bool> {
        if !self.echo_task_status() {
            let mut echo_stream = match self.connection.open_bi() {
                Some(bi) => bi,
                None => return Ok(false),
            }
            .await?;
            let buf = [
                self.password.as_bytes(),
                &[b'\r', b'\n', 0xff, b'\r', b'\n'],
            ]
            .concat();
            echo_stream.0.write_all(&buf).await?;
            let (echo_tx, echo_rx) = mpsc::channel::<()>(1);
            self.echo_tx = Some(echo_tx);
            tokio::spawn(new_echo_task(echo_stream, echo_rx));
        }

        let _ = self.echo_tx.as_mut().unwrap().try_send(());

        Ok(IS_CONNECTION_OPENED.load(SeqCst))
    }

    pub async fn connect(&mut self) -> Result<(SendStream, RecvStream)> {
        if !self.connection.has_remaining() || !self.echo().await? {
            debug!("[connect] re-connecting");
            self.new_connection().await?;
        }

        debug!("[connect] connection request");
        let new_tunnel = self.connection.open_bi().unwrap().await?;
        Ok(new_tunnel)
    }

    async fn new_connection(&mut self) -> Result<()> {
        let new_conn = timeout(
            Duration::from_secs(2),
            self.inner.connect(&self.remote, &self.remote_url)?,
        )
        .await
        .map_err(|e| Error::new(e))?
        .map_err(|e| Error::new(e))?;

        let quinn::NewConnection {
            connection: conn, ..
        } = new_conn;
        self.connection.refresh(conn);
        IS_CONNECTION_OPENED.store(true, SeqCst);
        Ok(())
    }
}

async fn new_builder(options: &Opt) -> Result<EndpointBuilder> {
    let mut builder = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(ALPN_QUIC_HTTP);

    load_cert(options, &mut client_config).await?;

    let mut cfg = client_config.build();
    let tls_cfg = Arc::get_mut(&mut cfg.crypto).unwrap();
    tls_cfg
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let transport_cfg = Arc::get_mut(&mut cfg.transport).unwrap();
    transport_cfg.max_idle_timeout(Some(MAX_IDLE_TIMEOUT))?;
    transport_cfg.persistent_congestion_threshold(6);
    transport_cfg.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS as u64)?;
    transport_cfg.packet_threshold(4);

    builder.default_client_config(cfg);

    Ok(builder)
}

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

pub async fn quic_tunnel_rx(options: &Opt) -> Result<(Endpoint, Incoming)> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(MAX_IDLE_TIMEOUT))?;
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

macro_rules! break_none {
    ($options:expr) => {
        match $options {
            None => {
                break;
            }
            Some(x) => x,
        }
    };
}

pub async fn quic_connection_daemon(
    context: TrojanContext,
    mut task_rx: mpsc::Receiver<oneshot::Sender<Result<(SendStream, RecvStream)>>>,
) -> Result<()> {
    debug!("quic_connection_daemon enter");
    let mut endpoint = EndpointManager::new(&context)
        .await
        .expect("EndpointManager::new");

    loop {
        let _ = break_none!(task_rx.recv().await).send(endpoint.connect().await);
    }
    debug!("quic_connection_daemon leave");

    Ok(())
}

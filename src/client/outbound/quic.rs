use crate::args::{Opt, TrojanContext};
use crate::client::ClientConnectionRequest;
use crate::utils::{ClientServerConnection, MixAddrType};
use anyhow::*;
use lazy_static::lazy_static;
use quinn::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use std::{net::SocketAddr, sync::atomic::Ordering::SeqCst};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::sleep;
use tokio::time::timeout;
use tokio::{fs, io};
use tracing::*;

use crate::protocol::*;

use super::forward;

lazy_static! {
    pub static ref IS_CONNECTION_OPENED: AtomicBool = AtomicBool::new(false);
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

pub async fn send_echo(echo_stream: (SendStream, RecvStream), mut echo_rx: mpsc::Receiver<()>) {
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
    shudown_tx: broadcast::Sender<()>,
}

impl EndpointManager {
    pub async fn new(context: &TrojanContext) -> Result<Self> {
        let (inner, _) = new_builder(&context.options)
            .await?
            .bind(&"[::]:0".parse().unwrap())?;
        let remote = context.remote_socket_addr;
        let remote_url = context.options.proxy_url.clone();

        let password = context.options.password_hash.clone();
        let (shudown_tx, _) = broadcast::channel(1);
        let mut _self = Self {
            inner,
            connection: QuicConnectionWrapper::default(),
            remote,
            remote_url,
            password,
            echo_tx: None,
            shudown_tx,
        };

        _self.new_connection().await?;

        Ok(_self)
    }

    fn echo_task_status(&self) -> bool {
        match self.echo_tx {
            Some(ref tx) => !tx.is_closed(),
            None => false,
        }
    }

    async fn echo(&mut self) -> Result<bool> {
        if !self.echo_task_status() {
            let open_conn = self.connection.open_bi();
            let connect_to_server = async move {
                match open_conn {
                    Some(bi) => Ok(ClientServerConnection::Quic(bi.await?)),
                    None => Err::<ClientServerConnection, Error>(anyhow!("failed to open bi conn")),
                }
            };

            let (echo_tx, echo_rx) = mpsc::channel::<()>(1);
            let incomming_request = async {
                Ok((
                    ClientConnectionRequest::ECHO(echo_rx),
                    MixAddrType::new_null(),
                ))
            };

            self.echo_tx = Some(echo_tx);

            tokio::spawn(forward(
                self.shudown_tx.subscribe(),
                self.password.clone(),
                incomming_request,
                connect_to_server,
            ));
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

    tls_cfg.root_store =
        rustls_native_certs::load_native_certs().expect("could not load platform certs");

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
                    error!("failed to open local server certificate: {:#}", e);
                }
                return Err(anyhow::Error::new(e));
            }
        }
    }
    Ok(())
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

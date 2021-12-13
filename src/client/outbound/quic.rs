use super::forward;
use crate::{
    args::{Opt, TrojanContext},
    client::utils::{get_rustls_config, ClientConnectionRequest, ClientServerConnection},
    protocol::*,
    utils::MixAddrType,
};
use anyhow::{anyhow, Error, Result};
use quinn::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc,
    },
    time::Duration,
};
use tokio::{
    fs, io, select,
    sync::{broadcast, mpsc, oneshot},
    time::{sleep, timeout},
};
use tokio_rustls::{rustls, rustls::RootCertStore};
use tracing::*;

pub static IS_CONNECTION_OPENED: AtomicBool = AtomicBool::new(false);

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
    outbound: Endpoint,
    connection: QuicConnectionWrapper,
    options: Arc<Opt>,
    echo_tx: Option<mpsc::Sender<()>>,
    shudown_tx: broadcast::Sender<()>,
}

impl EndpointManager {
    pub async fn new(options: Arc<Opt>) -> Result<Self> {
        let mut outbound = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
        outbound.set_default_client_config(new_builder(&options).await?);

        let (shudown_tx, _) = broadcast::channel(1);
        let mut _self = Self {
            outbound,
            connection: QuicConnectionWrapper::default(),
            options,
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
            let open_bi = match self.connection.open_bi() {
                None => return Err(anyhow!("failed to open bi conn")),
                Some(open_bi) => open_bi,
            };
            let connecting: _ =
                async move { Ok::<_, Error>(ClientServerConnection::Quic(open_bi.await?)) };

            let (echo_tx, echo_rx) = mpsc::channel::<()>(1);
            let incomming: _ = async {
                Ok((
                    ClientConnectionRequest::ECHO(echo_rx),
                    MixAddrType::new_null(),
                ))
            };

            self.echo_tx = Some(echo_tx);
            let context = TrojanContext {
                options: self.options.clone(),
                shutdown: self.shudown_tx.subscribe(),
            };

            tokio::spawn(forward(context, incomming, connecting));
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
            self.outbound.connect(
                self.options.remote_socket_addr.unwrap(),
                &self.options.server_hostname,
            )?,
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

async fn new_builder(options: &Opt) -> Result<quinn::ClientConfig> {
    let mut crypto_config = get_rustls_config(load_cert(options, RootCertStore::empty()).await?);
    crypto_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let mut config = quinn::ClientConfig::new(Arc::new(crypto_config));

    let transport_cfg = Arc::get_mut(&mut config.transport).unwrap();
    transport_cfg.max_idle_timeout(Some(QUIC_MAX_IDLE_TIMEOUT.try_into()?));
    transport_cfg.persistent_congestion_threshold(6);
    transport_cfg.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.try_into()?);
    transport_cfg.packet_threshold(4);
    Ok(config)
}

async fn load_cert(options: &Opt, mut roots: RootCertStore) -> Result<RootCertStore> {
    if let Some(ca_path) = &options.ca {
        roots.add(&rustls::Certificate(fs::read(&ca_path).await?))?;
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")).await {
            Ok(cert) => {
                roots.add(&rustls::Certificate(cert))?;
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
    Ok(roots)
}

pub async fn quic_connection_daemon(
    context: TrojanContext,
    mut task_rx: mpsc::Receiver<oneshot::Sender<Result<(SendStream, RecvStream)>>>,
) -> Result<()> {
    debug!("quic_connection_daemon enter");
    let TrojanContext {
        mut shutdown,
        options,
    } = context;
    let mut endpoint = EndpointManager::new(options)
        .await
        .expect("EndpointManager::new");

    loop {
        select! {
            maybe_ret_tx = task_rx.recv() => {
                match maybe_ret_tx {
                    None => break,
                    Some(ret_tx) => {
                        let _ =ret_tx.send(endpoint.connect().await);
                    },
                }
            }
            _ = shutdown.recv() => {
                break;
            }
        }
    }
    debug!("quic_connection_daemon leave");
    Ok(())
}

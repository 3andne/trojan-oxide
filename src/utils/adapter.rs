use std::{fmt, time::Duration};

use crate::utils::{copy_to_tls, either_io::EitherIO, Splitable, TimeoutMonitor};
use anyhow::{anyhow, Context, Result};
use futures::future::{pending, Either};
use tokio::{
    io::{copy, AsyncWriteExt},
    select,
    sync::broadcast,
};

pub enum AdapterTlsConfig {
    TcpOnly,
    RustlsUpload,
    RustlsDownload,
}

#[macro_export]
macro_rules! adapt {
    (Tcp, Tcp) => {Adapter::new_tcp_only()};
    (Tls, Tcp) => {Adapter::new_tls_download()};
    (Tcp, Tls) => {Adapter::new_tls_upload()};
    ([$traffic:expr][$conn_id:ident]$inbound:ident[$itype:ident] <=> $outbound:ident[$otype:ident] <=> $target_host:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[allow(unused_mut)]
        let mut adapter = adapt!($itype, $otype);
        $(adapter.set_timeout($timeout);)?
        info!("[{}][{}] => {:?}", $traffic, $conn_id, $target_host);
        let reason = adapter.relay($inbound, $outbound, $shutdown).await?;
        info!("[{}][{}] end by {}", $traffic, $conn_id, reason);
    };
}

pub enum StreamStopReasons {
    Upload,
    Download,
    Timeout,
    Shutdown,
}

impl fmt::Display for StreamStopReasons {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use StreamStopReasons::*;
        match self {
            Upload => write!(f, "upload"),
            Download => write!(f, "download"),
            Timeout => write!(f, "timeout"),
            Shutdown => write!(f, "shutdown"),
        }
    }
}

pub struct Adapter {
    tls_config: AdapterTlsConfig,
    timeout: Option<u16>,
}

impl Adapter {
    pub fn new_tcp_only() -> Self {
        Self {
            tls_config: AdapterTlsConfig::TcpOnly,
            timeout: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_tls_download() -> Self {
        Self {
            tls_config: AdapterTlsConfig::RustlsDownload,
            timeout: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_tls_upload() -> Self {
        Self {
            tls_config: AdapterTlsConfig::RustlsUpload,
            timeout: None,
        }
    }

    #[allow(dead_code)]
    pub fn set_timeout(&mut self, timeout: u16) {
        self.timeout = Some(timeout);
    }

    pub async fn relay<I, O>(
        &self,
        inbound: I,
        outbound: O,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<StreamStopReasons>
    where
        I: Splitable,
        O: Splitable,
    {
        let (out_read, out_write): _ = outbound.split();
        let (mut in_read, mut in_write): _ = inbound.split();

        let (mut out_read, mut out_write, timeout): _ = match self.timeout {
            Some(t) => {
                let deadline = Duration::from_secs(t as u64);
                let timeout_monitor = TimeoutMonitor::new(deadline);
                let out_read: _ = EitherIO::Left(timeout_monitor.watch(out_read));
                let out_write: _ = EitherIO::Left(timeout_monitor.watch(out_write));
                (out_read, out_write, Either::Left(timeout_monitor))
            }
            None => (
                EitherIO::Right(out_read),
                EitherIO::Right(out_write),
                Either::Right(pending::<()>()),
            ),
        };

        use AdapterTlsConfig::*;
        use Either::*;
        let download: _ = match self.tls_config {
            RustlsDownload => Left(copy_to_tls(&mut out_read, &mut in_write)),
            _ => Right(copy(&mut out_read, &mut in_write)),
        };

        let upload: _ = match self.tls_config {
            RustlsUpload => Left(copy_to_tls(&mut in_read, &mut out_write)),
            _ => Right(copy(&mut in_read, &mut out_write)),
        };

        use StreamStopReasons::*;
        let reason = select! {
            _ = download => {
                Download
            },
            _ = upload => {
                Upload
            },
            _ = timeout => {
                Timeout
            }
            _ = shutdown.recv() => {
                Shutdown
            },
        };
        in_write
            .shutdown()
            .await
            .with_context(|| anyhow!("failed to shutdown inbound"))?;
        out_write
            .shutdown()
            .await
            .with_context(|| anyhow!("failed to shutdown outbound"))?;
        Ok(reason)
    }
}

use std::{fmt, time::Duration};

use crate::utils::{copy_to_tls, copy_udp, either_io::EitherIO, TimeoutMonitor};
use anyhow::{anyhow, Context, Result};
use futures::future::{pending, Either};
use tokio::{
    io::{copy, AsyncRead, AsyncWrite, AsyncWriteExt},
    select,
    sync::broadcast,
};

use super::{UdpRead, UdpWrite, UdpWriteExt};

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
    (tcp) => {"tcp"};
    (lite) => {"lite"};
    ([udp][$conn_id:ident]$inbound:ident <=> $outbound:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[allow(unused_mut)]
        let mut adapter = Adapter::new_tcp_only();
        $(adapter.set_timeout($timeout);)?
        info!("[udp][{}]", $conn_id);
        let inbound = $inbound.split();
        let outbound = $outbound.split();
        let reason = adapter.relay_udp(inbound, outbound, $shutdown, $conn_id).await.with_context(|| anyhow!("[udp][{}] failed", $conn_id))?;
        info!("[udp][{}] end by {}", $conn_id, reason);
    };
    ([$traffic:ident][$conn_id:ident]$inbound:ident[$itype:ident] <=> $outbound:ident[$otype:ident] <=> $target_host:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[allow(unused_mut)]
        let mut adapter = adapt!($itype, $otype);
        $(adapter.set_timeout($timeout);)?
        info!("[{}][{}] => {:?}", adapt!($traffic), $conn_id, $target_host);
        let inbound = $inbound.split();
        let outbound = $outbound.split();
        let reason = adapter.relay_tcp(inbound, outbound, $shutdown).await.with_context(|| anyhow!("[{}][{}] failed", adapt!($traffic), $conn_id))?;
        info!("[{}][{}] end by {}", adapt!($traffic), $conn_id, reason);
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

    pub async fn relay_tcp<IR, IW, OR, OW>(
        &self,
        (mut in_read, mut in_write): (IR, IW),
        (out_read, out_write): (OR, OW),
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<StreamStopReasons>
    where
        IR: AsyncRead + Unpin,
        IW: AsyncWrite + Unpin,
        OR: AsyncRead + Unpin,
        OW: AsyncWrite + Unpin,
    {
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

    pub async fn relay_udp<IR, IW, OR, OW>(
        &self,
        (mut in_read, mut in_write): (IR, IW),
        (out_read, out_write): (OR, OW),
        mut shutdown: broadcast::Receiver<()>,
        conn_id: usize,
    ) -> Result<StreamStopReasons>
    where
        IR: UdpRead + Unpin,
        IW: UdpWrite + Unpin,
        OR: UdpRead + Unpin,
        OW: UdpWrite + Unpin,
    {
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

        use StreamStopReasons::*;
        let reason = select! {
            _ = copy_udp(&mut out_read, &mut in_write, None) => {
                Download
            },
            _ = copy_udp(&mut in_read, &mut out_write, Some(conn_id)) => {
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

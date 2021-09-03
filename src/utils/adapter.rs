use std::{fmt, time::Duration};

use crate::utils::{copy_forked, copy_udp, either_io::EitherIO, TimeoutMonitor};

use anyhow::{anyhow, Context, Result};
use futures::future::{pending, Either};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    select,
    sync::broadcast,
};

#[cfg(all(target_os = "linux", feature = "zio"))]
use {crate::VEC_TCP_TX, anyhow::Error, tokio::net::TcpStream};

use super::{UdpRead, UdpWrite, UdpWriteExt};

#[macro_export]
macro_rules! adapt {
    (tcp) => {"tcp"};
    (lite) => {"lite"};
    ([udp][$conn_id:ident]$inbound:ident <=> $outbound:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[allow(unused_mut)]
        let mut adapter = Adapter::new();
        $(adapter.set_timeout($timeout);)?
        info!("[udp][{}]", $conn_id);
        let inbound = $inbound.split();
        let outbound = $outbound.split();
        let reason = adapter.relay_udp(inbound, outbound, $shutdown, $conn_id).await.with_context(|| anyhow!("[udp][{}] failed", $conn_id))?;
        info!("[udp][{}] end by {}", $conn_id, reason);
    };
    ([lite][$conn_id:ident]$inbound:ident <=> $outbound:ident <=> $target_host:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[cfg(all(target_os = "linux", feature = "zio"))]
        {
            // timeout is not used here. In glommio, we set tcp socket's
            // timeout instead.
            info!("[lite+][{}] => {:?}", $conn_id, $target_host);
            let _ = Adapter::relay_tcp_zio($inbound, $outbound, $conn_id).await?;
            // the ending message is printed by glommio, since
            // it's not yet possible to get the reason back from glommio.
            // // info!("[lite+][{}] end by {}", $conn_id, reason);
        }

        #[cfg(not(all(target_os = "linux", feature = "zio")))]
        {
            #[allow(unused_mut)]
            let mut adapter = Adapter::new();
            $(adapter.set_timeout($timeout);)?
            info!("[lite][{}] => {:?}", $conn_id, $target_host);
            let mut inbound = $inbound;
            let inbound = inbound.split();
            let outbound = $outbound.split();
            let reason = adapter.relay_tcp(inbound, outbound, $shutdown).await.with_context(|| anyhow!("[lite][{}] failed", $conn_id))?;
            info!("[lite][{}] end by {}", $conn_id, reason);
        }
    };
    ([tcp][$conn_id:ident]$inbound:ident <=> $outbound:ident <=> $target_host:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[allow(unused_mut)]
        let mut adapter = Adapter::new();
        $(adapter.set_timeout($timeout);)?
        info!("[tcp][{}] => {:?}", $conn_id, $target_host);
        let inbound = $inbound.split();
        let outbound = $outbound.split();
        let reason = adapter.relay_tcp(inbound, outbound, $shutdown).await.with_context(|| anyhow!("[tcp][{}] failed", $conn_id))?;
        info!("[tcp][{}] end by {}", $conn_id, reason);
    };
}

#[derive(Debug, Clone)]
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
    timeout: Option<u16>,
}

impl Adapter {
    pub fn new() -> Self {
        Self { timeout: None }
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

        let download: _ = copy_forked(&mut out_read, &mut in_write);
        let upload: _ = copy_forked(&mut in_read, &mut out_write);

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

    #[cfg(all(target_os = "linux", feature = "zio"))]
    pub async fn relay_tcp_zio(
        inbound: TcpStream,
        outbound: TcpStream,
        conn_id: usize,
    ) -> Result<()> {
        let vec_tcp_tx = VEC_TCP_TX.get().unwrap();
        let tcp_tx = vec_tcp_tx[conn_id % vec_tcp_tx.len()].clone();

        // we transfer the ownership of the socket to glommio by sending
        // its std representation. tokio is no longer responsible for
        // releasing the socket.
        let inbound_std = inbound.into_std()?;
        let outbound_std = outbound.into_std()?;
        tcp_tx
            .send((inbound_std, outbound_std, conn_id))
            .await
            .map_err(|e| Error::new(e).context("failed on sending"))?;
        Ok(())
    }
}

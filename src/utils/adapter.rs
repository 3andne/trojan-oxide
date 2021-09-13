use std::{fmt, time::Duration};

use crate::utils::{
    copy_bidirectional_forked, either_io::EitherIO, udp_copy_bidirectional, TimeoutMonitor,
};

use anyhow::Result;
use futures::future::{pending, Either};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    select,
    sync::broadcast,
};
use tracing::debug;

#[cfg(all(target_os = "linux", feature = "zio"))]
use {crate::VEC_TCP_TX, anyhow::Error, tokio::net::TcpStream};

use super::{UdpRead, UdpWrite};

#[macro_export]
macro_rules! adapt {
    (tcp) => {"tcp"};
    (lite) => {"lite"};
    ([udp][$conn_id:ident]$inbound:ident <=> $outbound:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[allow(unused_mut)]
        let mut adapter = Adapter::new();
        $(adapter.set_timeout($timeout);)?
        info!("[udp][{}]", $conn_id);
        let reason = adapter.relay_udp($inbound, $outbound, $shutdown, $conn_id).await.with_context(|| anyhow!("[udp][{}] failed", $conn_id))?;
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
            let reason = adapter.relay_tcp($inbound, $outbound, $shutdown).await.with_context(|| anyhow!("[lite][{}] failed", $conn_id))?;
            info!("[lite][{}] end by {}", $conn_id, reason);
        }
    };
    ([tcp][$conn_id:ident]$inbound:ident <=> $outbound:ident <=> $target_host:ident Until $shutdown:ident$( Or Sec $timeout:expr)?) => {
        #[allow(unused_mut)]
        let mut adapter = Adapter::new();
        $(adapter.set_timeout($timeout);)?
        info!("[tcp][{}] => {:?}", $conn_id, $target_host);
        let reason = adapter.relay_tcp($inbound, $outbound, $shutdown).await.with_context(|| anyhow!("[tcp][{}] failed", $conn_id))?;
        info!("[tcp][{}] end by {}", $conn_id, reason);
    };
}

#[derive(Clone)]
#[cfg_attr(feature = "debug_info", derive(Debug))]
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

    pub async fn relay_tcp<I, O>(
        &self,
        mut inbound: I,
        outbound: O,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<StreamStopReasons>
    where
        I: AsyncRead + AsyncWrite + Unpin,
        O: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut outbound, timeout): _ = match self.timeout {
            Some(t) => {
                let deadline = Duration::from_secs(t as u64);
                let timeout_monitor = TimeoutMonitor::new(deadline);
                let outbound = EitherIO::Left(timeout_monitor.watch(outbound));
                (outbound, Either::Left(timeout_monitor))
            }
            None => (EitherIO::Right(outbound), Either::Right(pending::<()>())),
        };

        let duplex_stream: _ = copy_bidirectional_forked(&mut outbound, &mut inbound);

        use StreamStopReasons::*;
        let reason = select! {
            res = duplex_stream => {
                match res {
                    Err((reason, e)) => {
                        debug!("forward tcp failed: {:#}", e);
                        reason
                    }
                    Ok(res) => res,
                }
            },
            _ = timeout => {
                Timeout
            }
            _ = shutdown.recv() => {
                Shutdown
            },
        };
        Ok(reason)
    }

    pub async fn relay_udp<I, O>(
        &self,
        mut inbound: I,
        outbound: O,
        mut shutdown: broadcast::Receiver<()>,
        conn_id: usize,
    ) -> Result<StreamStopReasons>
    where
        I: UdpRead + UdpWrite + Unpin,
        O: UdpRead + UdpWrite + Unpin,
    {
        let (mut outbound, timeout): _ = match self.timeout {
            Some(t) => {
                let deadline = Duration::from_secs(t as u64);
                let timeout_monitor = TimeoutMonitor::new(deadline);
                let outbound: _ = EitherIO::Left(timeout_monitor.watch(outbound));
                (outbound, Either::Left(timeout_monitor))
            }
            None => (EitherIO::Right(outbound), Either::Right(pending::<()>())),
        };

        use StreamStopReasons::*;
        let reason = select! {
            res = udp_copy_bidirectional(&mut inbound, &mut outbound, conn_id) => {
                let (_, _, reason) = res?;
                reason
            }
            _ = timeout => {
                Timeout
            }
            _ = shutdown.recv() => {
                Shutdown
            },
        };
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

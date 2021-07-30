use std::time::Duration;

use crate::{
    server::Splitable,
    utils::{copy_to_tls, either_io::EitherIO, TimeoutMonitor},
};
use anyhow::Result;
use futures::future::{pending, Either};
use tokio::{io::copy, select, sync::broadcast};
use tracing::*;

pub enum AdapterTlsPort {
    TcpOnly,
    RustlsUpload,
    RustlsDownload,
}

pub struct Adapter {
    tls_config: AdapterTlsPort,
    timeout: Option<u16>,
    conn_id: u32,
}

impl Adapter {
    pub fn new(tls_config: AdapterTlsPort, timeout: Option<u16>, conn_id: u32) -> Self {
        Self {
            tls_config,
            timeout,
            conn_id,
        }
    }

    pub async fn relay<I, O>(
        &self,
        inbound: I,
        outbound: O,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<()>
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

        use AdapterTlsPort::*;
        use Either::*;
        let download: _ = match self.tls_config {
            RustlsDownload => Left(copy_to_tls(&mut out_read, &mut in_write)),
            _ => Right(copy(&mut out_read, &mut in_write)),
        };

        let upload: _ = match self.tls_config {
            RustlsUpload => Left(copy_to_tls(&mut in_read, &mut out_write)),
            _ => Right(copy(&mut in_read, &mut out_write)),
        };

        select! {
            res = download => {
                debug!("[{}]tcp relaying download end, {:?}", self.conn_id, res);
            },
            res = upload => {
                debug!("[{}]tcp relaying upload end, {:?}", self.conn_id, res);
            },
            _ = timeout => {
                debug!("[{}]end timeout", self.conn_id);
            }
            _ = shutdown.recv() => {
                debug!("[{}]shutdown signal received", self.conn_id);
            },
        }

        Ok(())
    }
}

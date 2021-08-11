// use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::IntoRawFd;
use std::time::Duration;

use glommio::net::TcpStream;
use glommio::{Local, LocalExecutorBuilder};
use tokio::sync::mpsc;

use super::copy_bidirectional::glommio_copy_bidirectional;
use super::{TcpRx, TcpTaskRet, TcpTx};
use glommio::Result;
use tracing::*;

// use tokio::net::TcpStream;

use crate::utils::StreamStopReasons;

async fn tcp_relay_task(mut inbound: TcpStream, mut outbound: TcpStream, ret: TcpTaskRet) {
    match glommio_copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(_) => {
            let _ = ret.send(StreamStopReasons::Download);
        }
        Err(e) => {
            error!("glommio copy failed: {:?}", e);
        }
    }
}

fn init_tcp_stream(std_tcp_stream: std::net::TcpStream) -> Result<TcpStream, ()> {
    let stream: TcpStream = unsafe {
        // safety: both steps are infallible, therefore the socket
        // will always be under control.
        let raw_fd = std_tcp_stream.into_raw_fd();
        TcpStream::from_raw_fd(raw_fd)
    };
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    Ok(stream)
}

async fn worker(mut tcp_rx: TcpRx) {
    while let Some((inbound_fd, outbound_fd, ret)) = tcp_rx.recv().await {
        let inbound = match init_tcp_stream(inbound_fd) {
            Ok(s) => s,
            Err(e) => {
                error!("glommio initing tcp inbound failed, {:?}", e);
                return;
            }
        };
        let outbound = match init_tcp_stream(outbound_fd) {
            Ok(s) => s,
            Err(e) => {
                error!("glommio initing tcp outbound failed, {:?}", e);
                return;
            }
        };
        Local::local(tcp_relay_task(inbound, outbound, ret)).detach();
    }
}

pub fn start_tcp_relay_threads() -> Vec<TcpTx> {
    let numc = num_cpus::get();
    let mut tcp_submit = Vec::with_capacity(numc);
    for i in 0..numc {
        debug!("starting glommio runtime: {}", i);
        let (tcp_tx, tcp_rx) = mpsc::channel(100);
        tcp_submit.push(tcp_tx);
        std::thread::spawn(move || {
            let ex = LocalExecutorBuilder::new().pin_to_cpu(i).make().unwrap();
            ex.run(Local::local(worker(tcp_rx)));
        });
    }
    tcp_submit
}

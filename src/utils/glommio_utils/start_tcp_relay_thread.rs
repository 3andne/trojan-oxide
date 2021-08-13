// use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::IntoRawFd;
use std::time::Duration;

use glommio::net::TcpStream;
use glommio::{Local, LocalExecutorBuilder};
use tokio::sync::mpsc;
use tokio::time::sleep;

use super::copy_bidirectional::glommio_copy_bidirectional;
use super::{TcpRx, TcpTaskRet, TcpTx};
use glommio::Result;
use tracing::*;

// use tokio::net::TcpStream;

use crate::utils::{Adapter, StreamStopReasons};

async fn tcp_relay_task(mut inbound: TcpStream, mut outbound: TcpStream, ret: TcpTaskRet) {
    debug!("tcp_relay_task: entered");
    match glommio_copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(_) => {
            debug!("tcp_relay_task: Ok");
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
            ex.run(worker(tcp_rx));
        });
    }
    tcp_submit
}

#[tokio::test]
async fn test_glommio() {
    use crate::VEC_TCP_TX;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let collector = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(collector);

    let tcp_submit = start_tcp_relay_threads();
    let _ = VEC_TCP_TX.set(tcp_submit);

    // spawn a server in tokio
    tokio::spawn(async move {
        let server_listener = tokio::net::TcpListener::bind("0.0.0.0:5555").await.unwrap();
        info!("server started");
        loop {
            let mut stream = match server_listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    error!("server[1] {:?}", e);
                    continue;
                }
            };
            // info!("server incoming");

            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            error!("server[2] {:?}", e);
                            return;
                        }
                    };

                    let _ = stream.write(&buf[..n]).await;
                }
            });
        }
    });

    // start the proxy
    tokio::spawn(async move {
        let proxy_listener = tokio::net::TcpListener::bind("0.0.0.0:6666").await.unwrap();
        info!("proxy started");

        let mut conn_id = 0;
        loop {
            let inbound = match proxy_listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    error!("proxy[1] {:?}", e);
                    continue;
                }
            };
            // info!("proxy incoming");

            conn_id += 1;

            tokio::spawn(async move {
                let outbound = match tokio::net::TcpStream::connect("127.0.0.1:5555").await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("proxy[2] {:?}", e);
                        return;
                    }
                };
                match Adapter::relay_tcp_zio(inbound, outbound, conn_id).await {
                    Ok(x) => info!("{}", x),
                    Err(x) => error!("proxy[3] {:?}", x),
                }
            });
        }
    });

    // spawn 100 clients in tokio
    let mut client_handles = Vec::new();
    for _ in 0..500 {
        client_handles.push(tokio::spawn(async move {
            let mut client_sender = match tokio::net::TcpStream::connect("127.0.0.1:6666").await {
                Ok(s) => s,
                Err(e) => {
                    error!("client[1] {:?}", e);
                    return;
                }
            };
            let data = [1u8; 2048];
            let mut buf = [0u8; 2048];
            for _ in 0..10 {
                let _ = client_sender.write(&data).await;
                let _ = client_sender.read(&mut buf).await;
                sleep(Duration::from_secs(1)).await;
            }
        }));
    }

    let mut i = 0;
    for handles in client_handles {
        info!("client {}", i);
        i += 1;
        let _ = handles.await;
    }
}

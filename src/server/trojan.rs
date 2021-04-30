use crate::{server::*, utils::ParserError};
use anyhow::{Error, Result};
use futures::{StreamExt, TryFutureExt};
use quinn::*;
use std::sync::Arc;
use tokio::{io::*, select};
use tokio::{net::TcpStream, sync::broadcast};
use tracing::*;

pub async fn handle_quic_connection(
    mut streams: IncomingBiStreams,
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);

    loop {
        let stream = select! {
            s = streams.next() => {
                match s {
                    Some(stream) => stream,
                    None => {break;}
                }
            },
            _ = upper_shutdown.recv() => {
                // info
                break;
            }
        };

        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::Error::new(e));
            }
            Ok(s) => s,
        };
        let shutdown = shutdown_tx.subscribe();
        let pass_copy = password_hash.clone();
        tokio::spawn(
            handle_quic_outbound(stream, shutdown, pass_copy).map_err(|e| {
                trace!("handle_quic_outbound quit due to {:?}", e);
                e
            }),
        );
    }
    todo!()
}

async fn handle_quic_outbound(
    stream: (SendStream, RecvStream),
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
) -> Result<()> {
    let (mut in_write, mut in_read) = stream;
    let mut buffer = Vec::with_capacity(128);
    let mut target = Target::new(password_hash.as_bytes());
    loop {
        let read = in_read.read_buf(&mut buffer).await?;
        if read != 0 {
            match target.parse(&buffer) {
                Err(ParserError::Invalid) => {
                    trace!("invalid");
                    return Err(Error::new(ParserError::Invalid));
                }
                Err(ParserError::Incomplete) => {
                    trace!("Incomplete");
                    continue;
                }
                Ok(()) => {
                    trace!("Ok");
                    break;
                }
            }
        } else {
            return Err(Error::new(ParserError::Invalid));
        }
    }

    trace!("outbound trying to connect");

    let mut outbound = if target.host.is_ip() {
        TcpStream::connect(target.host.to_socket_addrs(target.port)).await?
    } else {
        TcpStream::connect(target.host.unwrap_hostname() + &":" + &target.port.to_string()).await?
    };
    trace!("outbound connected: {:?}", outbound);

    if target.cursor < buffer.len() {
        trace!(
            "remaining packet: {:?}",
            String::from_utf8(buffer[target.cursor..].to_vec())
        );
        let mut t = std::io::Cursor::new(&buffer[target.cursor..]);
        outbound.write_buf(&mut t).await?;
        outbound.flush().await?;
    }

    let (mut out_read, mut out_write) = outbound.split();

    trace!("server start relaying");
    select! {
        _ = tokio::io::copy(&mut out_read, &mut in_write) => {
            trace!("server relaying upload end");
        },
        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
            trace!("server relaying download end");
        },
        _ = upper_shutdown.recv() => {
            trace!("server shutdown signal received");
        },
    }

    Ok(())
}

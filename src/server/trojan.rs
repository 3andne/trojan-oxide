use crate::{server::*, utils::ParserError};
use anyhow::{Error, Result};
use futures::{StreamExt, TryFutureExt};
use quinn::*;
use std::sync::Arc;
use tokio::{io::*, select};
use tokio::{net::TcpStream, sync::broadcast};

pub async fn send_udp_packet0<A>(
    addr: MixAddrType,
    outbound: &mut A,
    password: Arc<String>,
) -> Result<()>
where
    A: AsyncWrite + Unpin + ?Sized,
{
    todo!()
}

pub async fn send_tcp_packet0<A>(
    addr: &MixAddrType,
    outbound: &mut A,
    password: Arc<String>,
) -> Result<()>
where
    A: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = Vec::with_capacity(HASH_LEN + 2 + 1 + addr.encoded_len() + 2);
    buf.extend_from_slice(password.as_bytes());
    buf.extend_from_slice(&[b'\r', b'\n', 1]);
    addr.write_buf(&mut buf);
    buf.extend_from_slice(&[b'\r', b'\n']);
    outbound.write_all(&buf).await?;
    // not using the following code because of quinn's bug.
    // let packet0 = [
    //     IoSlice::new(password_hash.as_bytes()),
    //     IoSlice::new(&command0[..command0_len]),
    //     IoSlice::new(self.host.as_bytes()),
    //     IoSlice::new(&port_arr),
    //     IoSlice::new(&[b'\r', b'\n']),
    // ];
    // let mut writer = Pin::new(outbound);
    // future::poll_fn(|cx| writer.as_mut().poll_write_vectored(cx, &packet0[..]))
    //     .await
    //     .map_err(|e| Box::new(e))?;

    // writer.flush().await.map_err(|e| Box::new(e))?;
    outbound.flush().await?;
    debug!("trojan packet 0 sent");

    Ok(())
}

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
                debug!("handle_quic_outbound quit due to {:?}", e);
                e
            }),
        );
    }
    Ok(())
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
                    debug!("invalid");
                    return Err(Error::new(ParserError::Invalid));
                }
                Err(ParserError::Incomplete) => {
                    debug!("Incomplete");
                    continue;
                }
                Ok(()) => {
                    debug!("Ok");
                    break;
                }
            }
        } else {
            return Err(Error::new(ParserError::Invalid));
        }
    }

    debug!("outbound trying to connect");

    let mut outbound = if target.host.is_ip() {
        TcpStream::connect(target.host.to_socket_addrs()).await?
    } else {
        TcpStream::connect(target.host.host_repr()).await?
    };
    debug!("outbound connected: {:?}", outbound);

    if target.cursor < buffer.len() {
        debug!(
            "remaining packet: {:?}",
            String::from_utf8(buffer[target.cursor..].to_vec())
        );
        let mut t = std::io::Cursor::new(&buffer[target.cursor..]);
        outbound.write_buf(&mut t).await?;
        outbound.flush().await?;
    }

    let (mut out_read, mut out_write) = outbound.split();

    debug!("server start relaying");
    select! {
        _ = tokio::io::copy(&mut out_read, &mut in_write) => {
            debug!("server relaying upload end");
        },
        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
            debug!("server relaying download end");
        },
        _ = upper_shutdown.recv() => {
            debug!("server shutdown signal received");
        },
    }

    Ok(())
}

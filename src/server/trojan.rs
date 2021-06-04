use crate::{
    server::*,
    utils::{copy_udp, ConnectionRequest, ServerUdpStream},
};
use anyhow::Result;
use futures::{StreamExt, TryFutureExt};
use std::sync::Arc;
use tokio::{io::*, select};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::broadcast,
};

pub async fn trojan_connect_udp<A>(outbound: &mut A, password: Arc<String>) -> Result<()>
where
    A: AsyncWrite + Unpin + ?Sized,
{
    let addr = MixAddrType::V4(([0, 0, 0, 0], 0));
    trojan_connect(true, &addr, outbound, password).await
}

pub async fn trojan_connect_tcp<A>(
    addr: &MixAddrType,
    outbound: &mut A,
    password: Arc<String>,
) -> Result<()>
where
    A: AsyncWrite + Unpin + ?Sized,
{
    trojan_connect(false, addr, outbound, password).await
}

async fn trojan_connect<A>(
    udp: bool,
    addr: &MixAddrType,
    outbound: &mut A,
    password: Arc<String>,
) -> Result<()>
where
    A: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = Vec::with_capacity(HASH_LEN + 2 + 1 + addr.encoded_len() + 2);
    buf.extend_from_slice(password.as_bytes());
    buf.extend_from_slice(&[b'\r', b'\n', if udp { 0x03 } else { 0x01 }]);
    addr.write_buf(&mut buf);
    buf.extend_from_slice(&[b'\r', b'\n']);
    debug!("trojan_connect: writing {:?}", buf);
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
    let mut target = Target::new(password_hash.as_bytes());
    use ConnectionRequest::*;
    match target.accept(stream).await {
        Ok(TCP((mut in_write, mut in_read))) => {
            let mut outbound = if target.host.is_ip() {
                TcpStream::connect(target.host.to_socket_addrs()).await?
            } else {
                TcpStream::connect(target.host.host_repr()).await?
            };
            debug!("outbound connected: {:?}", outbound);

            if target.cursor < target.buf.len() {
                debug!(
                    "remaining packet: {:?}",
                    String::from_utf8(target.buf[target.cursor..].to_vec())
                );
                let mut t = std::io::Cursor::new(&target.buf[target.cursor..]);
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
        }
        Ok(UDP((mut in_write, mut in_read))) => {
            let outbound = UdpSocket::bind(":::0").await?;
            info!("[udp] {:?} =>", outbound.local_addr());
            let mut udp_stream = ServerUdpStream::new(outbound);
            let (mut out_write, mut out_read) = udp_stream.split();

            select! {
                _ = copy_udp(&mut out_read, &mut in_write) => {
                    debug!("udp relaying upload end");
                },
                _ = copy_udp(&mut in_read, &mut out_write) => {
                    debug!("udp relaying download end");
                },
            }
        }
        Err(_) => {
            todo!()
        }
    }

    Ok(())
}

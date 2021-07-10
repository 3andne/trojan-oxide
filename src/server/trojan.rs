use crate::{
    server::*,
    utils::{
        copy_udp,
        debug_reader_writer::{DebugAsyncReader, DebugAsyncWriter},
        ClientServerConnection, ConnectionRequest, ServerUdpStream,
    },
};
use anyhow::Result;
use futures::{StreamExt, TryFutureExt};
use lazy_static::lazy_static;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::{io::split, select};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::broadcast,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

lazy_static! {
    static ref CONNECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
}

pub async fn trojan_connect_udp(
    outbound: &mut ClientServerConnection,
    password: Arc<String>,
) -> Result<()> {
    let addr = MixAddrType::V4(([0, 0, 0, 0], 0));
    match outbound {
        // ClientServerConnection::Quic((out_write, _)) => {
        //     trojan_connect(true, &addr, out_write, password).await
        // }
        ClientServerConnection::TcpTLS(out_write) => {
            trojan_connect(true, &addr, out_write, password).await
        }
    }
}

pub async fn trojan_connect_tcp(
    addr: &MixAddrType,
    outbound: &mut ClientServerConnection,
    password: Arc<String>,
) -> Result<()> {
    match outbound {
        // ClientServerConnection::Quic((out_write, _)) => {
        //     trojan_connect(false, addr, out_write, password).await
        // }
        ClientServerConnection::TcpTLS(out_write) => {
            trojan_connect(false, addr, out_write, password).await
        }
    }
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
    trace!("trojan_connect: writing {:?}", buf);
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

// pub async fn handle_quic_connection(
//     mut streams: IncomingBiStreams,
//     mut upper_shutdown: broadcast::Receiver<()>,
//     password_hash: Arc<String>,
//     fallback_port: Arc<String>,
// ) -> Result<()> {
//     let (shutdown_tx, _) = broadcast::channel(1);

//     loop {
//         let stream = select! {
//             s = streams.next() => {
//                 match s {
//                     Some(stream) => stream,
//                     None => {break;}
//                 }
//             },
//             _ = upper_shutdown.recv() => {
//                 // info
//                 break;
//             }
//         };

//         let stream = match stream {
//             Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
//                 info!("connection closed");
//                 return Ok(());
//             }
//             Err(e) => {
//                 return Err(anyhow::Error::new(e));
//             }
//             Ok(s) => QuicStream::new(s),
//         };
//         let shutdown = shutdown_tx.subscribe();
//         let pass_copy = password_hash.clone();
//         let fallback_port_clone = fallback_port.clone();
//         tokio::spawn(
//             handle_outbound(stream, shutdown, pass_copy, fallback_port_clone).map_err(|e| {
//                 debug!("handle_quic_outbound quit due to {:?}", e);
//                 e
//             }),
//         );
//     }
//     Ok(())
// }

pub async fn handle_tcp_tls_connection(
    stream: TlsStream<TcpStream>,
    upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    fallback_port: Arc<String>,
) -> Result<()> {
    handle_outbound(stream, upper_shutdown, password_hash, fallback_port)
        .await
        .unwrap_or_else(move |e| error!("connection failed: {reason}", reason = e.to_string()));
    Ok(())
}

async fn copy_tcp<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W) -> Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let len = r.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        w.write(&buf[..len]).await?;
        w.flush().await?;
    }
    Ok(())
}

pub async fn handle_outbound(
    stream: TlsStream<TcpStream>,
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
    fallback_port: Arc<String>,
) -> Result<()> {
    let mut target = Target::new(password_hash.as_bytes(), fallback_port);
    use ConnectionRequest::*;
    match target.accept(stream).await {
        Ok(TCP((mut in_write, mut in_read))) => {
            let outbound = if target.host.is_ip() {
                TcpStream::connect(target.host.to_socket_addrs()).await?
            } else {
                TcpStream::connect(target.host.host_repr()).await?
            };
            // debug!("outbound connected: {:?}", outbound);

            // todo: refactor with BufferedRecv
            let (mut out_read, mut out_write) = split(outbound);
            if target.cursor < target.buf.len() {
                debug!(
                    "remaining packet: {:?}",
                    String::from_utf8(target.buf[target.cursor..].to_vec())
                );
                // let mut t = std::io::Cursor::new(&target.buf[target.cursor..]);
                out_write.write_all(&target.buf[target.cursor..]).await?;
                out_write.flush().await?;
            }

            let conn_id = CONNECTION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            info!("[tcp][{}]start relaying", conn_id);
            // let mut in_read = DebugAsyncReader::new(in_read);
            // let mut out_read = DebugAsyncReader::new(out_read);
            // let mut in_write = DebugAsyncWriter::new(in_write);
            // let mut out_write = DebugAsyncWriter::new(out_write);
            select! {
                // _ = tokio::io::copy(&mut out_read, &mut in_write) => {
                _ = copy_tcp(&mut out_read, &mut in_write) => {
                    debug!("server relaying upload end");
                },
                // _ = tokio::io::copy(&mut in_read, &mut out_write) => {
                _ = copy_tcp(&mut in_read, &mut out_write) => {
                    debug!("server relaying download end");
                },
                _ = upper_shutdown.recv() => {
                    debug!("server shutdown signal received");
                },
            }
            debug!("[tcp][{}]end relaying", conn_id);
        }
        Ok(UDP((mut in_write, mut in_read))) => {
            let outbound = UdpSocket::bind("[::]:0").await?;
            info!("[udp] {:?} =>", outbound.local_addr());
            let mut udp_stream = ServerUdpStream::new(outbound);
            let (mut out_write, mut out_read) = udp_stream.split();
            select! {
                res = copy_udp(&mut out_read, &mut in_write) => {
                    debug!("udp relaying download end: {:?}", res);
                },
                res = copy_udp(&mut in_read, &mut out_write) => {
                    debug!("udp relaying upload end: {:?}", res);
                },
            }
        }
        Ok(ECHO((mut in_write, mut in_read))) => {
            info!("[echo]start relaying");
            if target.cursor < target.buf.len() {
                debug!(
                    "remaining packet: {:?}",
                    String::from_utf8(target.buf[target.cursor..].to_vec())
                );
                let mut t = std::io::Cursor::new(&target.buf[target.cursor..]);
                in_write.write_buf(&mut t).await?;
                in_write.flush().await?;
            }
            select! {
                _ = tokio::io::copy(&mut in_read, &mut in_write) => {
                    debug!("server relaying upload end");
                },
                _ = upper_shutdown.recv() => {
                    debug!("server shutdown signal received");
                },
            }
            info!("[echo]end relaying");
        }
        Err(e) => {
            info!("invalid connection: {}", e);
        }
    }

    Ok(())
}

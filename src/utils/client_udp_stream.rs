use super::{CursoredBuffer, UdpRelayBuffer, MixAddrType};
use bytes::{BufMut, Buf};
use futures::ready;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

struct Socks5UdpSpecificBuffer {
    inner: Vec<u8>,
}

impl Socks5UdpSpecificBuffer {
    fn new(capacity: usize) -> Self {
        let mut inner = Vec::with_capacity(capacity);
        // The fields in the UDP request header are:
        //     o  RSV  Reserved X'0000'
        //     o  FRAG    Current fragment number
        inner.extend_from_slice(&[0, 0, 0]);
        Self { inner }
    }

    fn reset(&mut self) {
        unsafe {
            self.inner.set_len(3);
        }
    }

    fn is_empty(&self) -> bool {
        assert!(
            self.inner.len() >= 3,
            "Socks5UdpSpecificBuffer unexpected len: {}",
            self.inner.len()
        );
        self.inner.len() == 3
    }
}

impl Deref for Socks5UdpSpecificBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Socks5UdpSpecificBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct Socks5UdpStream {
    server_udp_socket: UdpSocket,
    client_udp_addr: Option<SocketAddr>,
}

pub struct Socks5UdpRecvStream<'a> {
    server_udp_socket: &'a UdpSocket,
    client_udp_addr: Option<SocketAddr>,
    addr_tx: Option<oneshot::Sender<SocketAddr>>,
}

impl<'a> Socks5UdpRecvStream<'a> {
    fn new(server_udp_socket: &'a UdpSocket, addr_tx: oneshot::Sender<SocketAddr>) -> Self {
        Self {
            server_udp_socket,
            client_udp_addr: None,
            addr_tx: Some(addr_tx),
        }
    }
}

pub struct Socks5UdpSendStream<'a> {
    server_udp_socket: &'a UdpSocket,
    client_udp_addr: Option<SocketAddr>,
    addr_rx: Option<oneshot::Receiver<SocketAddr>>,
    buffer: Socks5UdpSpecificBuffer,
}

impl<'a> Socks5UdpSendStream<'a> {
    fn new(server_udp_socket: &'a UdpSocket, addr_tx: oneshot::Receiver<SocketAddr>) -> Self {
        Self {
            server_udp_socket,
            client_udp_addr: None,
            addr_rx: Some(addr_tx),
            buffer: Socks5UdpSpecificBuffer::new(2048),
        }
    }
}

impl Socks5UdpStream {
    pub fn new(server_udp_socket: UdpSocket) -> Self {
        Self {
            server_udp_socket,
            client_udp_addr: None,
        }
    }

    pub fn split<'a>(&'a self) -> (Socks5UdpRecvStream<'a>, Socks5UdpSendStream<'a>) {
        let (addr_tx, addr_rx) = oneshot::channel();
        (
            Socks5UdpRecvStream::new(&self.server_udp_socket, addr_tx),
            Socks5UdpSendStream::new(&self.server_udp_socket, addr_rx),
        )
    }
}

impl<'a> AsyncRead for Socks5UdpRecvStream<'a> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let addr = match ready!(self.server_udp_socket.poll_recv_from(cx, buf)) {
            Ok(addr) => addr,
            Err(e) => {
                return Poll::Ready(Err(e));
            }
        };

        if self.client_udp_addr.is_none() {
            self.client_udp_addr = Some(addr.clone());
            let addr_tx = match self.addr_tx.take() {
                Some(v) => v,
                None => {
                    return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                }
            };
            match addr_tx.send(addr) {
                Ok(_) => {
                    return Poll::Ready(Ok(()));
                }
                Err(_) => {
                    return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                }
            }
        } else {
            if !self.client_udp_addr.map(|v| v == addr).unwrap() {
                return Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<'a> Socks5UdpSendStream<'a> {
    fn poll_write_optioned(
        self: &mut std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: Option<&[u8]>,
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.client_udp_addr.is_none() {
            let maybe_addr = match self.addr_rx {
                Some(ref mut rx) => rx.try_recv(),
                None => {
                    return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                }
            };

            self.client_udp_addr = match maybe_addr {
                Ok(addr) => Some(addr),
                Err(_) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WouldBlock.into()));
                }
            }
        }

        let buf = match buf {
            Some(b) => b,
            None => &self.buffer,
        };

        Poll::Ready(ready!(self.server_udp_socket.poll_send_to(
            cx,
            buf,
            self.client_udp_addr.unwrap()
        )))
    }
}

impl<'a> AsyncWrite for Socks5UdpSendStream<'a> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        (&mut self).poll_write_optioned(cx, Some(buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

pub trait UdpRead {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<crate::utils::MixAddrType>>;
}

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// The fields in the UDP request header are:

//     o  RSV  Reserved X'0000'
//     o  FRAG    Current fragment number
//     o  ATYP    address type of following addresses:
//        o  IP V4 address: X'01'
//        o  DOMAINNAME: X'03'
//        o  IP V6 address: X'04'
//     o  DST.ADDR       desired destination address
//     o  DST.PORT       desired destination port
//     o  DATA     user data
impl<'a> UdpRead for Socks5UdpRecvStream<'a> {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<MixAddrType>> {
        let mut buf_inner = buf.as_read_buf();
        let ptr = buf_inner.filled().as_ptr();
        match ready!(self.poll_read(cx, &mut buf_inner)) {
            Ok(_) => {
                // Ensure the pointer does not change from under us
                assert_eq!(ptr, buf_inner.filled().as_ptr());
                let n = buf_inner.filled().len();
                // Safety: This is guaranteed to be the number of initialized (and read)
                // bytes due to the invariants provided by `ReadBuf::filled`.
                unsafe {
                    buf.advance_mut(n);
                }
                buf.advance(3);
                Poll::Ready(
                    MixAddrType::from_encoded(buf)
                        .map_err(|_| std::io::ErrorKind::Other.into()),
                )
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

pub trait UdpWrite {
    fn poll_proxy_stream_write(
        self: &mut Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>>;
}

impl<'a> UdpWrite for Socks5UdpSendStream<'a> {
    fn poll_proxy_stream_write(
        self: &mut Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>> {
        if self.buffer.is_empty() {
            addr.write_buf(&mut self.buffer);
            self.buffer.extend_from_slice(buf);
        }
        let res = self.poll_write_optioned(cx, None);
        if res.is_ready() {
            self.buffer.reset();
        }
        res
    }
}

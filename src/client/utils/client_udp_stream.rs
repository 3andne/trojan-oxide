use crate::{
    protocol::UDP_BUFFER_SIZE,
    utils::{CursoredBuffer, ExtendableFromSlice, MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite},
};
use futures::ready;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::{debug, warn};

#[cfg_attr(feature = "debug_info", derive(Debug))]
struct Socks5UdpSpecifiedBuffer {
    inner: Vec<u8>,
}

impl Socks5UdpSpecifiedBuffer {
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
            "Socks5UdpSpecifiedBuffer unexpected len: {}",
            self.inner.len()
        );
        self.inner.len() == 3
    }
}

impl ExtendableFromSlice for Socks5UdpSpecifiedBuffer {
    fn extend_from_slice(&mut self, src: &[u8]) {
        self.inner.extend_from_slice(src);
    }
}

impl Deref for Socks5UdpSpecifiedBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Socks5UdpSpecifiedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct Socks5UdpStream {
    server_udp_socket: UdpSocket,
    client_udp_addr: Option<SocketAddr>,
    signal_reset: oneshot::Receiver<()>,
    buffer: Socks5UdpSpecifiedBuffer,
}

impl Socks5UdpStream {
    pub fn new(
        server_udp_socket: UdpSocket,
        stream_reset_signal_rx: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            server_udp_socket,
            client_udp_addr: None,
            signal_reset: stream_reset_signal_rx,
            buffer: Socks5UdpSpecifiedBuffer::new(UDP_BUFFER_SIZE),
        }
    }
}

impl Socks5UdpStream {
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
        } else {
            if self.client_udp_addr.unwrap() != addr {
                return Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_write(
        self: &mut std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.client_udp_addr.is_none() {
            return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
        }

        self.server_udp_socket
            .poll_send_to(cx, &self.buffer, self.client_udp_addr.unwrap())
    }
}

impl UdpRead for Socks5UdpStream {
    /// ```not_rust
    /// +----+------+------+----------+----------+----------+
    /// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    /// +----+------+------+----------+----------+----------+
    /// | 2  |  1   |  1   | Variable |    2     | Variable |
    /// +----+------+------+----------+----------+----------+
    /// The fields in the UDP request header are:
    ///      o  RSV  Reserved X'0000'
    ///      o  FRAG    Current fragment number
    ///      o  ATYP    address type of following addresses:
    ///          o  IP V4 address: X'01'
    ///          o  DOMAINNAME: X'03'
    ///          o  IP V6 address: X'04'
    ///      o  DST.ADDR       desired destination address
    ///      o  DST.PORT       desired destination port
    ///      o  DATA     user data
    /// ```
    fn poll_proxy_stream_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<MixAddrType>> {
        debug!("Socks5UdpRecvStream::poll_proxy_stream_read()");
        let mut buf_inner = buf.as_read_buf();
        let ptr = buf_inner.filled().as_ptr();

        crate::try_recv!(
            oneshot,
            self.signal_reset,
            return Poll::Ready(Ok(MixAddrType::None))
        );

        match ready!(self.poll_read(cx, &mut buf_inner)) {
            Ok(_) => {
                // Ensure the pointer does not change from under us
                assert_eq!(ptr, buf_inner.filled().as_ptr());
                let n = buf_inner.filled().len();

                if n < 3 {
                    return Poll::Ready(Ok(MixAddrType::None));
                }

                // Safety: This is guaranteed to be the number of initialized (and read)
                // bytes due to the invariants provided by `ReadBuf::filled`.
                unsafe {
                    buf.advance_mut(n);
                }
                buf.advance(3);
                #[cfg(feature = "debug_info")]
                debug!(
                    "Socks5UdpRecvStream::poll_proxy_stream_read() buf {:?}",
                    buf
                );
                Poll::Ready(
                    MixAddrType::from_encoded(buf).map_err(|_| std::io::ErrorKind::Other.into()),
                )
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl UdpWrite for Socks5UdpStream {
    fn poll_proxy_stream_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>> {
        let just_filled_buf = if self.buffer.is_empty() {
            addr.write_buf(&mut self.buffer);
            self.buffer.extend_from_slice(buf);
            true
        } else {
            false
        };

        // only if we write the whole buf in one write we reset the buffer
        // to accept new data.
        match self.poll_write(cx)? {
            Poll::Ready(real_written_amt) => {
                if real_written_amt == self.buffer.len() {
                    self.buffer.reset();
                } else {
                    warn!("Socks5UdpSendStream didn't send the entire buffer");
                }
            }
            _ => (),
        }

        if just_filled_buf {
            Poll::Ready(Ok(buf.len()))
        } else {
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

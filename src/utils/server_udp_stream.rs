use super::{CursoredBuffer, MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite};
use bytes::Buf;
use futures::ready;
use pin_project_lite::pin_project;
use quinn::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

struct TrojanUdpRelayBuffer {
    inner: Vec<u8>,
    cursor: usize,
}

impl CursoredBuffer for TrojanUdpRelayBuffer {
    fn chunk(&self) -> &[u8] {
        &self.inner[self.cursor..]
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.inner.len() >= self.cursor + len,
            "TrojanUdpRelayBuffer was about to set a larger position than it's length"
        );
        self.cursor += len;
    }
}

impl TrojanUdpRelayBuffer {
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn vec_mut(&mut self) -> &mut Vec<u8> {
        &mut self.inner
    }

    unsafe fn reset(&mut self) {
        self.inner.set_len(0);
    }
}

impl Deref for TrojanUdpRelayBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.chunk()
    }
}

pin_project! {
    struct TrojanUdpSendStream {
        #[pin]
        inner: SendStream,
        buffer: TrojanUdpRelayBuffer
    }
}

impl TrojanUdpSendStream {
    pub fn new(inner: SendStream) -> Self {
        Self {
            inner,
            buffer: TrojanUdpRelayBuffer {
                inner: Vec::with_capacity(2048),
                cursor: 0,
            },
        }
    }
}

impl UdpWrite for TrojanUdpSendStream {
    /// ```not_rust
    /// +------+----------+----------+--------+---------+----------+
    /// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
    /// +------+----------+----------+--------+---------+----------+
    /// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
    /// +------+----------+----------+--------+---------+----------+
    /// ```
    fn poll_proxy_stream_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>> {
        if self.buffer.is_empty() {
            addr.write_buf(self.buffer.vec_mut());
            self.buffer
                .vec_mut()
                .extend_from_slice(&buf.len().to_be_bytes());
            self.buffer.vec_mut().extend_from_slice(buf);
        }
        let me = self.project();
        // if we're not sending the entire buffer, we resend it
        match me.inner.poll_write(cx, &me.buffer) {
            Poll::Ready(Ok(x)) if x < me.buffer.remaining() => {
                // warn!("Socks5UdpSendStream didn't send the entire buffer");
                me.buffer.advance(x);
                Poll::Pending
            }
            res @ Poll::Ready(_) => {
                unsafe { me.buffer.reset() };
                res
            }
            res => res,
            _ => todo!("understand the `pin_project` magics"),
        }
    }
}

pin_project! {
    struct TrojanUdpRecvStream {
        #[pin]
        inner: RecvStream,
        buffer: TrojanUdpRelayBuffer
    }
}

impl UdpRead for TrojanUdpRecvStream {
    /// ```not_rust
    /// +------+----------+----------+--------+---------+----------+
    /// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
    /// +------+----------+----------+--------+---------+----------+
    /// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
    /// +------+----------+----------+--------+---------+----------+
    /// ```
    fn poll_proxy_stream_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<MixAddrType>> {
        todo!("totally untouched");
        let mut buf_inner = buf.as_read_buf();
        let ptr = buf_inner.filled().as_ptr();

        let me = self.project();

        match ready!(me.inner.poll_read(cx, &mut buf_inner)) {
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
                Poll::Ready(
                    MixAddrType::from_encoded(buf).map_err(|_| std::io::ErrorKind::Other.into()),
                )
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

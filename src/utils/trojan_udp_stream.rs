use super::{
    CursoredBuffer, ExtendableFromSlice, MixAddrType, ParserError, UdpRead, UdpRelayBuffer,
    UdpWrite,
};
use futures::ready;
use pin_project_lite::pin_project;
use quinn::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

pin_project! {
    pub struct TrojanUdpSendStream {
        #[pin]
        inner: SendStream,
        buffer: UdpRelayBuffer
    }
}

impl TrojanUdpSendStream {
    pub fn new(inner: SendStream) -> Self {
        Self {
            inner,
            buffer: UdpRelayBuffer::new(),
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
            addr.write_buf(&mut self.buffer);
            self.buffer.extend_from_slice(&buf.len().to_be_bytes());
            self.buffer.extend_from_slice(buf);
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
    pub struct TrojanUdpRecvStream {
        #[pin]
        inner: RecvStream,
        buffer: UdpRelayBuffer,
        expecting: Option<usize>,
        addr_buf: MixAddrType,
    }
}

impl TrojanUdpRecvStream {
    pub fn new(inner: RecvStream) -> Self {
        Self {
            inner,
            buffer: UdpRelayBuffer::new(),
            expecting: None,
            addr_buf: MixAddrType::None,
        }
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<MixAddrType>> {
        let me = self.project();
        let mut buf_inner = me.buffer.as_read_buf();
        let ptr = buf_inner.filled().as_ptr();
        match ready!(me.inner.poll_read(cx, &mut buf_inner)) {
            Ok(_) => {
                // Ensure the pointer does not change from under us
                assert_eq!(ptr, buf_inner.filled().as_ptr());
                let n = buf_inner.filled().len();

                // Safety: This is guaranteed to be the number of initialized (and read)
                // bytes due to the invariants provided by `ReadBuf::filled`.
                unsafe {
                    buf.advance_mut(n);
                }

                if me.addr_buf.is_none() {
                    match MixAddrType::from_encoded(buf) {
                        Ok(addr) => {
                            *me.addr_buf = addr;
                        }
                        Err(ParserError::Incomplete) => {
                            return Poll::Pending;
                        }
                        Err(ParserError::Invalid) => {
                            return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                        }
                    }
                }

                if me.expecting.is_none() {
                    if me.buffer.remaining() < 2 {
                        return Poll::Pending;
                    }
                    *me.expecting =
                        Some(u16::from_be_bytes([buf.chunk()[0], buf.chunk()[1]]) as usize);
                    me.buffer.advance(2);
                }

                if me.expecting.unwrap() <= me.buffer.remaining() {
                    let expecting = me.expecting.unwrap();
                    buf.extend_from_slice(&me.buffer.chunk()[..expecting]);
                    me.buffer.advance(expecting);
                    me.buffer.pump();
                    *me.expecting = None;
                    let addr = std::mem::replace(me.addr_buf, MixAddrType::None);
                    Poll::Ready(Ok(addr))
                } else {
                    Poll::Pending
                }
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

pub fn new_trojan_udp_stream(
    write: SendStream,
    read: RecvStream,
) -> (TrojanUdpSendStream, TrojanUdpRecvStream) {
    (
        TrojanUdpSendStream::new(write),
        TrojanUdpRecvStream::new(read),
    )
}

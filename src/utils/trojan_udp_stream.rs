use super::{
    BufferedRecv, CursoredBuffer, ExtendableFromSlice, MixAddrType, ParserError, UdpRead,
    UdpRelayBuffer, UdpWrite,
};
use futures::ready;
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::*;

pin_project! {
    #[derive(Debug)]
    pub struct TrojanUdpSendStream<W> {
        #[pin]
        // inner: SendStream,
        inner: W,
        buffer: UdpRelayBuffer
    }
}

impl<W> TrojanUdpSendStream<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buffer: UdpRelayBuffer::new(),
        }
    }
}

impl<W: AsyncWrite + Unpin> UdpWrite for TrojanUdpSendStream<W> {
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
        debug!("TrojanUdpSendStream::poll_proxy_stream_write()");
        let just_filled_buf = if self.buffer.is_empty() {
            addr.write_buf(&mut self.buffer);
            unsafe {
                self.buffer
                    .extend_from_slice(&(buf.len() as u16).to_be_bytes());
            }
            self.buffer.extend_from_slice(&[b'\r', b'\n']);
            self.buffer.extend_from_slice(buf);
            true
        } else {
            false
        };
        let me = self.project();

        debug!(
            "TrojanUdpSendStream::poll_proxy_stream_write() inner {:?}",
            me.buffer
        );

        match me.inner.poll_write(cx, &me.buffer)? {
            Poll::Ready(x) => {
                if x < me.buffer.remaining() {
                    debug!(
                        "TrojanUdpSendStream::poll_proxy_stream_write() x < me.buffer.remaining() inner {:?}",
                        me.buffer
                    );
                    me.buffer.advance(x);
                } else {
                    debug!(
                        "TrojanUdpSendStream::poll_proxy_stream_write() reset buffer {:?}",
                        me.buffer
                    );
                    unsafe {
                        me.buffer.reset();
                    }
                }
            }
            Poll::Pending => {
                debug!(
                    "TrojanUdpSendStream::poll_proxy_stream_write() pending {:?}",
                    me.buffer
                );
            }
            _ => todo!("understand the `pin_project` magics"),
        }

        if just_filled_buf {
            Poll::Ready(Ok(buf.len()))
        } else {
            Poll::Pending
        }
    }
}

// pub type BufferedQuicRecvStream = BufferedRecv<RecvStream>;

pin_project! {
    #[derive(Debug)]
    pub struct TrojanUdpRecvStream<R> {
        #[pin]
        inner: BufferedRecv<R>,
        buffer: UdpRelayBuffer,
        expecting: Option<usize>,
        addr_buf: MixAddrType,
    }
}

impl<R> TrojanUdpRecvStream<R> {
    pub fn new(inner: BufferedRecv<R>) -> Self {
        Self {
            inner,
            buffer: UdpRelayBuffer::new(),
            expecting: None,
            addr_buf: MixAddrType::None,
        }
    }
}

impl<R: AsyncRead + Unpin> UdpRead for TrojanUdpRecvStream<R> {
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
        outer_buf: &mut UdpRelayBuffer, // bug once occured: accidentally used outer_buf as inner_buf
    ) -> Poll<std::io::Result<MixAddrType>> {
        debug!("TrojanUdpRecvStream::poll_proxy_stream_read()");
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
                    me.buffer.advance_mut(n);
                }

                debug!(
                    "TrojanUdpRecvStream::poll_proxy_stream_read() buf {:?}",
                    me.buffer
                );

                if me.addr_buf.is_none() {
                    match MixAddrType::from_encoded(me.buffer) {
                        Ok(addr) => {
                            *me.addr_buf = addr;
                        }
                        Err(ParserError::Incomplete(msg)) => {
                            error!(
                                "TrojanUdpRecvStream::poll_proxy_stream_read Incomplete({})",
                                msg
                            );
                            return Poll::Pending;
                        }
                        Err(ParserError::Invalid(msg)) => {
                            error!(
                                "TrojanUdpRecvStream::poll_proxy_stream_read Invalid({})",
                                msg
                            );
                            return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                        }
                    }
                }

                if me.expecting.is_none() {
                    if me.buffer.remaining() < 2 {
                        return Poll::Pending;
                    }
                    *me.expecting =
                        Some(
                            u16::from_be_bytes([me.buffer.chunk()[0], me.buffer.chunk()[1]])
                                as usize,
                        );
                    me.buffer.advance(2);

                    me.buffer.advance(2); // for `\r\n`
                }

                if me.expecting.unwrap() <= me.buffer.remaining() {
                    let expecting = me.expecting.unwrap();
                    outer_buf.extend_from_slice(&me.buffer.chunk()[..expecting]);
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

pub fn new_trojan_udp_stream<R, W>(
    write: W,
    read: R,
    buffered_request: Option<Vec<u8>>,
) -> (TrojanUdpSendStream<W>, TrojanUdpRecvStream<R>) {
    (
        TrojanUdpSendStream::new(write),
        TrojanUdpRecvStream::new(BufferedRecv::<R>::new(read, buffered_request)),
    )
}

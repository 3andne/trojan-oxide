use crate::utils::{
    BufferedRecv, CursoredBuffer, ExtendableFromSlice, MixAddrType, ParserError, UdpRead,
    UdpRelayBuffer, UdpWrite,
};
use futures::ready;
use pin_project_lite::pin_project;
use std::{
    io::Result,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::*;

pin_project! {
    #[cfg_attr(feature = "debug_info", derive(Debug))]
    pub struct TrojanUdpStream<IO> {
        #[pin]
        inner: BufferedRecv<IO>,
        // recv half
        recv_buffer: UdpRelayBuffer,
        expecting: Option<usize>,
        addr_buf: MixAddrType,
        // send half
        send_buffer: UdpRelayBuffer,
        data_len: usize,
    }
}

impl<IO> TrojanUdpStream<IO> {
    pub fn new(inner: IO, buffered_request: Option<(usize, Vec<u8>)>) -> Self {
        Self {
            inner: BufferedRecv::new(inner, buffered_request),
            recv_buffer: UdpRelayBuffer::new(),
            expecting: None,
            addr_buf: MixAddrType::None,
            send_buffer: UdpRelayBuffer::new(),
            data_len: 0,
        }
    }

    fn try_update_addr_buf(self: Pin<&mut Self>) -> Poll<Result<()>> {
        let me = self.project();
        if me.addr_buf.is_none() {
            match MixAddrType::from_encoded(me.recv_buffer) {
                Ok(addr) => {
                    #[cfg(feature = "udp_info")]
                    debug!("TrojanUdpRecvStream addr {:?}", addr);
                    *me.addr_buf = addr;
                    Poll::Ready(Ok(()))
                }
                Err(ParserError::Incomplete(msg)) => {
                    error!("TrojanUdpRecvStream Incomplete({})", msg);
                    Poll::Pending
                }
                Err(ParserError::Invalid(msg)) => {
                    error!("TrojanUdpRecvStream Invalid({})", msg);
                    Poll::Ready(Err(std::io::ErrorKind::Other.into()))
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn try_update_expecting(self: Pin<&mut Self>) -> Poll<()> {
        let me = self.project();
        if me.expecting.is_none() {
            if me.recv_buffer.remaining() < 2 {
                return Poll::Pending;
            }
            *me.expecting =
                Some(
                    u16::from_be_bytes([me.recv_buffer.chunk()[0], me.recv_buffer.chunk()[1]])
                        as usize,
                );
            me.recv_buffer.advance(2);

            me.recv_buffer.advance(2); // for `\r\n`
        }
        Poll::Ready(())
    }

    fn try_extract_packet(
        mut self: Pin<&mut Self>,
        outer_buf: &mut UdpRelayBuffer,
    ) -> Poll<Result<MixAddrType>> {
        #[cfg(feature = "udp_info")]
        debug!("TrojanUdpRecvStream buf after addr {:?}", self.recv_buffer);

        ready!(self.as_mut().try_update_addr_buf()?);
        ready!(self.as_mut().try_update_expecting());

        let me = self.project();

        let expecting = me.expecting.unwrap();
        // udp shouldn't be fragmented
        // we read in the packet as a whole
        // or we return pending
        if expecting <= me.recv_buffer.remaining() {
            outer_buf.extend_from_slice(&me.recv_buffer.chunk()[..expecting]);
            me.recv_buffer.advance(expecting);
            me.recv_buffer.pump();
            *me.expecting = None;
            #[cfg(feature = "udp_info")]
            debug!(
                "TrojanUdpRecvStream buffer before return {:?}",
                me.recv_buffer
            );
            let addr = std::mem::replace(me.addr_buf, MixAddrType::None);
            Poll::Ready(Ok(addr))
        } else {
            Poll::Pending
        }
    }
}

impl<W: AsyncWrite + Unpin> UdpWrite for TrojanUdpStream<W> {
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
    ) -> Poll<Result<usize>> {
        #[cfg(feature = "udp_info")]
        debug!("TrojanUdpSendStream::poll_proxy_stream_write()");
        if self.send_buffer.is_empty() {
            self.data_len = buf.len();
            addr.write_buf(&mut self.send_buffer);
            // unsafe: as u16
            self.send_buffer
                .extend_from_slice(&(buf.len() as u16).to_be_bytes());
            self.send_buffer.extend_from_slice(&[b'\r', b'\n']);
            self.send_buffer.extend_from_slice(buf);
        }
        let me = self.project();

        #[cfg(feature = "udp_info")]
        debug!(
            "TrojanUdpSendStream::poll_proxy_stream_write() inner {:?}",
            me.send_buffer
        );

        match me.inner.poll_write(cx, &me.send_buffer)? {
            Poll::Ready(0) => {
                return Poll::Ready(Ok(0));
            }
            Poll::Ready(x) => {
                if x < me.send_buffer.remaining() {
                    #[cfg(feature = "udp_info")]
                    debug!(
                        "TrojanUdpSendStream::poll_proxy_stream_write() x < me.buffer.remaining() inner {:?}",
                        me.send_buffer
                    );
                    me.send_buffer.advance(x);
                    Poll::Pending
                } else {
                    #[cfg(feature = "udp_info")]
                    debug!(
                        "TrojanUdpSendStream::poll_proxy_stream_write() reset buffer {:?}",
                        me.send_buffer
                    );
                    unsafe {
                        me.send_buffer.reset();
                    }
                    Poll::Ready(Ok(*me.data_len))
                }
            }
            Poll::Pending => {
                #[cfg(feature = "udp_info")]
                debug!(
                    "TrojanUdpSendStream::poll_proxy_stream_write() pending {:?}",
                    me.send_buffer
                );
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<R: AsyncRead + Unpin> UdpRead for TrojanUdpStream<R> {
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
        outer_buf: &mut UdpRelayBuffer, // bug once occured: accidentally used outer_buf as inner_buf
    ) -> Poll<Result<MixAddrType>> {
        #[cfg(feature = "udp_info")]
        debug!("TrojanUdpRecvStream::poll_proxy_stream_read()");
        if self.recv_buffer.len() > 0 {
            if let res @ Poll::Ready(_) = self.as_mut().try_extract_packet(outer_buf) {
                return res;
            }
        }

        let mut me = self.as_mut().project();
        let mut buf_inner = me.recv_buffer.as_read_buf();
        let ptr = buf_inner.filled().as_ptr();
        match ready!(me.inner.as_mut().poll_read(cx, &mut buf_inner)) {
            Ok(_) => {
                // Ensure the pointer does not change from under us
                assert_eq!(ptr, buf_inner.filled().as_ptr());
                let n = buf_inner.filled().len();

                if n == 0 {
                    // EOF is seen
                    return Poll::Ready(Ok(MixAddrType::None));
                }

                // Safety: This is guaranteed to be the number of initialized (and read)
                // bytes due to the invariants provided by `ReadBuf::filled`.
                unsafe {
                    me.recv_buffer.advance_mut(n);
                }

                #[cfg(feature = "udp_info")]
                debug!(
                    "TrojanUdpRecvStream::poll_proxy_stream_read() buf {:?}",
                    me.recv_buffer
                );
            }
            Err(e) => return Poll::Ready(Err(e)),
        }

        self.try_extract_packet(outer_buf)
    }
}

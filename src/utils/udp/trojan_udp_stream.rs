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
        want_to_extract: bool,
        // send half
        send_buffer: UdpRelayBuffer,
        data_len: usize,
    }
}

mod mc {
    macro_rules! debug_info {
        (recv $me:expr, $msg:expr, $addition:expr) => {
            #[cfg(feature = "udp_info")]
            debug!(
                "TrojanUdpRecv {} buf len {} expecting {:?} addr {:?} | {:?}",
                $msg,
                $me.recv_buffer.chunk().len(),
                $me.expecting,
                $me.addr_buf,
                $addition
            );
        };

        (send $me:expr, $msg:expr, $buf:expr, $addr:expr, $addition:expr) => {
            #[cfg(feature = "udp_info")]
            debug!(
                "TrojanUdpSend {} inner_buf len {} buf len {} addr {:?} | {:?}",
                $msg,
                $me.send_buffer.chunk().len(),
                $buf.len(),
                $addr,
                $addition,
            );
        };
    }
    pub(crate) use debug_info;
}

impl<IO: Unpin> TrojanUdpStream<IO> {
    pub fn new(inner: IO, buffered_request: Option<(usize, Vec<u8>)>) -> Self {
        Self {
            inner: BufferedRecv::new(inner, buffered_request),
            recv_buffer: UdpRelayBuffer::new(),
            expecting: None,
            want_to_extract: false,
            addr_buf: MixAddrType::None,
            send_buffer: UdpRelayBuffer::new(),
            data_len: 0,
        }
    }
}

impl<W: AsyncWrite + Unpin> TrojanUdpStream<W> {
    fn copy_into_inner(mut self: Pin<&mut Self>, buf: &[u8], addr: &MixAddrType) {
        self.data_len = buf.len();
        self.send_buffer
            .reserve_by_cursor(addr.encoded_len() + 4 + buf.len());
        addr.write_buf(&mut self.send_buffer);
        // unsafe: as u16
        self.send_buffer
            .extend_from_slice(&(buf.len() as u16).to_be_bytes());
        self.send_buffer.extend_from_slice(&[b'\r', b'\n']);
        self.send_buffer.extend_from_slice(buf);
        mc::debug_info!(send self, "empty and refill", buf, addr, "");
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
        mc::debug_info!(send self, "enter", buf, addr, "");
        if self.send_buffer.is_empty() {
            self.as_mut().copy_into_inner(buf, addr);
        }
        let me = self.project();

        mc::debug_info!(send me, "before sending", buf, addr, "");

        match me.inner.poll_write(cx, &me.send_buffer)? {
            Poll::Ready(0) => {
                return Poll::Ready(Ok(0));
            }
            Poll::Ready(x) => {
                if x < me.send_buffer.remaining() {
                    mc::debug_info!(send me, "send and remain", buf, addr, x);
                    me.send_buffer.advance(x);
                    Poll::Pending
                } else {
                    mc::debug_info!(send me, "send all", buf, addr, x);
                    unsafe {
                        me.send_buffer.reset();
                    }
                    Poll::Ready(Ok(*me.data_len))
                }
            }
            Poll::Pending => {
                mc::debug_info!(send me, "pending", buf, addr, "");
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

impl<R: AsyncRead + Unpin> TrojanUdpStream<R> {
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
                Err(ParserError::Incomplete(_msg)) => {
                    #[cfg(feature = "udp_info")]
                    debug!("TrojanUdpRecvStream Incomplete({})", _msg);
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

    fn is_read_pending_by_small_buf(self: &Pin<&mut Self>) -> bool {
        self.recv_buffer.is_full() && self.expecting.unwrap() > self.recv_buffer.remaining()
    }

    fn try_update_expecting(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.expecting.is_none() {
            if self.recv_buffer.remaining() < 2 {
                return Poll::Pending;
            }
            let bytes = self.recv_buffer.chunk()[0..1].try_into().unwrap();
            let expecting = u16::from_be_bytes(bytes) as usize;
            self.expecting = Some(expecting);
            self.recv_buffer.advance(2 + 2); // `len` + `\r\n`

            if self.is_read_pending_by_small_buf() {
                // We should've read all in this poll, but the buffer was too small so we have to re-schedule manually.
                cx.waker().wake_by_ref();
                self.recv_buffer.reserve_by_cursor(expecting);
            }
        }
        Poll::Ready(())
    }

    fn copy_into_outer(mut self: Pin<&mut Self>, outer_buf: &mut UdpRelayBuffer) {
        let expecting = self.expecting.unwrap();
        let _out_len = outer_buf.len();
        outer_buf.extend_from_slice(&self.recv_buffer.chunk()[..expecting]);
        self.recv_buffer.advance(expecting);
        self.recv_buffer.compact();
        self.expecting = None;
        mc::debug_info!(recv self, "can extract", format!("outer len: {} -> {}", _out_len, outer_buf.len()));
    }

    fn try_extract_packet(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        outer_buf: &mut UdpRelayBuffer,
    ) -> Poll<Result<MixAddrType>> {
        mc::debug_info!(recv self, "try_extract_packet", "");
        ready!(self.as_mut().try_update_addr_buf()?);
        ready!(self.as_mut().try_update_expecting(cx));

        mc::debug_info!(recv self, "try to extract", "");

        // udp shouldn't be fragmented
        // we read in the packet as a whole
        // or we return pending
        if self.expecting.unwrap() <= self.recv_buffer.remaining() {
            self.as_mut().copy_into_outer(outer_buf);
            Poll::Ready(Ok(std::mem::replace(&mut self.addr_buf, MixAddrType::None)))
        } else {
            self.want_to_extract = false;
            Poll::Pending
        }
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
        mc::debug_info!(recv self, "enter", "");
        if self.want_to_extract {
            if let res @ Poll::Ready(_) = self.as_mut().try_extract_packet(cx, outer_buf) {
                cx.waker().wake_by_ref();
                mc::debug_info!(recv self, "early return", res);
                return res;
            }
        }

        let mut me = self.as_mut().project();
        let mut buf_inner = me.recv_buffer.as_read_buf();
        match me.inner.as_mut().poll_read(cx, &mut buf_inner)? {
            Poll::Ready(_) => {
                match buf_inner.filled().len() {
                    0 => {
                        mc::debug_info!(recv me, "n == 0", "");
                        // EOF is seen
                        Poll::Ready(Ok(MixAddrType::None))
                    }
                    n => {
                        // Safety: This is guaranteed to be the number of initialized (and read) bytes due to the invariants provided by `ReadBuf::filled`.
                        unsafe {
                            me.recv_buffer.advance_mut(n);
                        }

                        *me.want_to_extract = true;

                        mc::debug_info!(recv me, "read ready", n);

                        self.try_extract_packet(cx, outer_buf)
                    }
                }
            }
            Poll::Pending => {
                mc::debug_info!(recv me, "pending", "");
                Poll::Pending
            }
        }
    }
}

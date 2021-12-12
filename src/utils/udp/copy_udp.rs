use futures::ready;

use crate::utils::{CursoredBuffer, MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite};
use std::pin::Pin;
use std::task::Poll;
use std::{future::Future, u64};
#[cfg(feature = "debug_info")]
use tracing::debug;
use tracing::info;

#[allow(unused)]
pub async fn copy_udp<'a, R: UdpRead + Unpin, W: UdpWrite + Unpin>(
    reader: &'a mut R,
    writer: &'a mut W,
    conn_id: Option<usize>,
) -> std::io::Result<u64> {
    CopyUdp {
        reader,
        writer,
        udp_buf: UdpCopyBuf::new(conn_id),
    }
    .await
}

struct CopyUdp<'a, R, W> {
    reader: &'a mut R,
    writer: &'a mut W,
    udp_buf: UdpCopyBuf,
}

impl<R, W> Future for CopyUdp<'_, R, W>
where
    R: UdpRead + Unpin,
    W: UdpWrite + Unpin,
{
    type Output = std::io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        me.udp_buf
            .poll_copy(cx, Pin::new(me.reader), Pin::new(me.writer))
    }
}

pub(crate) struct UdpCopyBuf {
    buf: UdpRelayBuffer,
    addr: Option<MixAddrType>,
    amt: u64,
    conn_id: Option<usize>,
}

impl UdpCopyBuf {
    pub(crate) fn new(conn_id: Option<usize>) -> Self {
        Self {
            buf: UdpRelayBuffer::new(),
            addr: None,
            amt: 0,
            conn_id,
        }
    }

    pub(crate) fn poll_copy<R, W>(
        self: &mut Self,
        cx: &mut std::task::Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<std::io::Result<u64>>
    where
        R: UdpRead + Unpin,
        W: UdpWrite + Unpin,
    {
        loop {
            if !self.buf.has_remaining() {
                #[cfg(feature = "debug_info")]
                debug!("[{:?}]CopyUdp::poll reset buffer", self.conn_id);
                unsafe {
                    self.buf.reset();
                }
                #[cfg(feature = "debug_info")]
                debug!("[{:?}]CopyUdp::poll self.addr.is_none()", self.conn_id);
                let new_addr = ready!(reader.as_mut().poll_proxy_stream_read(cx, &mut self.buf))?;
                if new_addr.is_none() {
                    #[cfg(feature = "debug_info")]
                    debug!("[{:?}]CopyUdp::poll new_addr.is_none()", self.conn_id);
                    break;
                }
                if self.addr.as_ref().map_or(true, |prev| prev != &new_addr) {
                    if self.conn_id.is_some() {
                        info!("[udp][{}] => {:?}", self.conn_id.unwrap(), &new_addr);
                    }
                    self.addr = Some(new_addr);
                }
            }

            #[cfg(feature = "debug_info")]
            debug!(
                "[{:?}]CopyUdp::poll self.addr {:?}, self.buff: {:?}",
                self.conn_id,
                self.addr,
                &self.buf.chunk()
            );

            let x = ready!(writer.as_mut().poll_proxy_stream_write(
                cx,
                &self.buf.chunk(),
                self.addr.as_ref().unwrap()
            ))?;

            ready!(writer.as_mut().poll_flush(cx))?; // for TlsStream

            if x == 0 {
                break;
            }

            #[cfg(feature = "debug_info")]
            debug!("[{:?}]CopyUdp::poll self.buf.advance({})", self.conn_id, x);
            self.buf.advance(x);
            self.amt += x as u64;
        }
        return Poll::Ready(Ok(self.amt));
    }
}

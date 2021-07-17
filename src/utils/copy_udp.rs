use futures::ready;

use super::{CursoredBuffer, MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite};
use std::fmt::Debug;
use std::pin::Pin;
use std::task::Poll;
use std::{future::Future, u64};
#[cfg(feature = "debug_info")]
use tracing::debug;
use tracing::info;

pub async fn copy_udp<'a, R: UdpRead + Unpin + Debug, W: UdpWrite + Unpin + Debug>(
    reader: &'a mut R,
    writer: &'a mut W,
    conn_id: Option<usize>,
) -> std::io::Result<u64> {
    CopyUdp {
        reader,
        writer,
        buf: UdpRelayBuffer::new(),
        addr: None,
        amt: 0,
        conn_id,
    }
    .await
}

struct CopyUdp<'a, R: UdpRead, W: UdpWrite> {
    reader: &'a mut R,
    writer: &'a mut W,
    buf: UdpRelayBuffer,
    addr: Option<MixAddrType>,
    amt: u64,
    conn_id: Option<usize>,
}

impl<R, W> Future for CopyUdp<'_, R, W>
where
    R: UdpRead + Unpin + Debug,
    W: UdpWrite + Unpin + Debug,
{
    type Output = std::io::Result<u64>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            if me.addr.is_none() {
                #[cfg(feature = "debug_info")]
                debug!("[{:?}]CopyUdp::poll me.addr.is_none()", me.conn_id);
                let new_addr =
                    ready!(Pin::new(&mut *me.reader).poll_proxy_stream_read(cx, &mut me.buf))?;
                if new_addr.is_none() {
                    #[cfg(feature = "debug_info")]
                    debug!("[{:?}]CopyUdp::poll new_addr.is_none()", me.conn_id);
                    break;
                }
                if me.conn_id.is_some() {
                    info!("[udp][{}] => {:?}", me.conn_id.unwrap(), &new_addr);
                }
                me.addr = Some(new_addr);
            }

            #[cfg(feature = "debug_info")]
            debug!(
                "[{:?}]CopyUdp::poll me.addr {:?}, me.buff: {:?}",
                me.conn_id,
                me.addr,
                &me.buf.chunk()
            );

            let x = ready!(Pin::new(&mut *me.writer).poll_proxy_stream_write(
                cx,
                &me.buf.chunk(),
                me.addr.as_ref().unwrap()
            ))?;

            if x == 0 {
                break;
            }

            #[cfg(feature = "debug_info")]
            debug!("[{:?}]CopyUdp::poll me.buf.advance({})", me.conn_id, x);
            me.buf.advance(x);

            if !me.buf.has_remaining() {
                #[cfg(feature = "debug_info")]
                debug!("[{:?}]CopyUdp::poll reset buffer", me.conn_id);
                me.addr = None;
                unsafe {
                    me.buf.reset();
                }
            }

            ready!(Pin::new(&mut *me.writer).poll_flush(cx))?; // for TlsStream
            me.amt += x as u64;
        }
        return Poll::Ready(Ok(me.amt));
    }
}

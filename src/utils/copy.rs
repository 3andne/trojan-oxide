use futures::ready;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{CursoredBuffer, MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite};
use anyhow::Result;
use std::fmt::Debug;
use std::pin::Pin;
use std::task::Poll;
use std::{future::Future, u64};
use tinyvec::TinyVec;
use tracing::debug;

const RELAY_BUFFER_SIZE: usize = 256;

pub async fn copy_udp<'a, R: UdpRead + Unpin + Debug, W: UdpWrite + Unpin + Debug>(
    reader: &'a mut R,
    writer: &'a mut W,
) -> std::io::Result<u64> {
    CopyUdp {
        reader,
        writer,
        buf: UdpRelayBuffer::new(),
        addr: None,
        amt: 0,
    }
    .await
}

struct CopyUdp<'a, R: UdpRead, W: UdpWrite> {
    reader: &'a mut R,
    writer: &'a mut W,
    buf: UdpRelayBuffer,
    addr: Option<MixAddrType>,
    amt: u64,
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
                debug!(
                    "[{:?} >> {:?}] CopyUdp::poll me.addr.is_none()",
                    me.reader, me.writer
                );
                let new_addr =
                    ready!(Pin::new(&mut *me.reader).poll_proxy_stream_read(cx, &mut me.buf))?;
                if new_addr.is_none() {
                    debug!("CopyUdp::poll new_addr.is_none()");
                    return Poll::Ready(Ok(me.amt));
                }
                me.addr = Some(new_addr);
            }

            debug!("CopyUdp::poll me.addr {:?}", me.addr);
            debug!(
                "CopyUdp::poll poll_proxy_stream_write() {:?}",
                &me.buf.chunk()
            );
            let x = ready!(Pin::new(&mut *me.writer).poll_proxy_stream_write(
                cx,
                &me.buf.chunk(),
                me.addr.as_ref().unwrap()
            ))?;

            debug!("CopyUdp::poll me.buf.advance({})", x);
            me.buf.advance(x);

            if !me.buf.has_remaining() {
                debug!("CopyUdp::poll reset buffer");
                me.addr = None;
                unsafe {
                    me.buf.reset();
                }
            }

            me.amt += x as u64;
        }
    }
}

pub async fn copy_tcp<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
) -> Result<()> {
    let mut buf = TinyVec::<[u8; RELAY_BUFFER_SIZE]>::new();
    loop {
        let len = r.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        w.write(&buf[..len]).await?;
        if len != buf.len() {
            w.flush().await?;
        }
    }
    Ok(())
}

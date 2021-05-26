use futures::ready;

use super::{
    client_udp_stream::{UdpRead, UdpWrite},
    CursoredBuffer, UdpRelayBuffer,
};
use std::future::Future;
use std::pin::Pin;

pub async fn copy_udp<'a, R: UdpRead + Unpin, W: UdpWrite + Unpin>(
    reader: &'a mut R,
    writer: &'a mut W,
) -> std::io::Result<u64> {
    CopyUdp { reader, writer }.await
}

struct CopyUdp<'a, R: UdpRead, W: UdpWrite> {
    reader: &'a mut R,
    writer: &'a mut W,
}

impl<R, W> Future for CopyUdp<'_, R, W>
where
    R: UdpRead + Unpin,
    W: UdpWrite + Unpin,
{
    type Output = std::io::Result<u64>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        todo!("in progress");
        let mut buf_vec = Vec::with_capacity(2048);
        let mut buf = UdpRelayBuffer::new(&mut buf_vec);
        let me = &mut *self;
        let addr = ready!(Pin::new(&mut *me.reader).poll_proxy_stream_read(cx, &mut buf))?;
        let x = ready!(Pin::new(&mut *me.writer).poll_proxy_stream_write(cx, buf.as_bytes(), &addr))?;

        todo!()
    }
}

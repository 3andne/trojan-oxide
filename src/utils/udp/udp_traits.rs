use crate::utils::{MixAddrType, UdpRelayBuffer};
use std::pin::Pin;
use std::task::{Context, Poll};

use super::udp_shutdown::{shutdown, Shutdown};

pub trait UdpRead {
    /// Should return Poll::Ready(Ok(MixAddrType::None)) when
    /// EOF is seen.
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<crate::utils::MixAddrType>>;
}

pub trait UdpWrite {
    /// Should return Ok(0) when the underlying object is no
    /// longer writable
    fn poll_proxy_stream_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>>;

    /// Should implement this if the underlying object e.g.
    /// TlsStream requires you to manually flush after write
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>;

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>>;
}

pub trait UdpWriteExt: UdpWrite {
    fn shutdown(&mut self) -> Shutdown<'_, Self>
    where
        Self: Unpin,
    {
        shutdown(self)
    }
}

impl<W: UdpWrite + ?Sized> UdpWriteExt for W {}

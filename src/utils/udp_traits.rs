use super::{UdpRelayBuffer, MixAddrType};
use std::pin::Pin;
use std::task::{Context, Poll};

pub trait UdpRead {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<crate::utils::MixAddrType>>;
}

pub trait UdpWrite {
    fn poll_proxy_stream_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>>;
}

use super::{
    CursoredBuffer, ExtendableFromSlice, MixAddrType, ParserError, UdpRead, UdpRelayBuffer,
    UdpWrite,
};
use futures::ready;
use quinn::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{UdpSocket},
};

pub struct ServerUdpStream {
    inner: UdpSocket,
}

impl ServerUdpStream {
    pub fn split(&mut self) -> (ServerUdpSendStream, ServerUdpRecvStream) {
        (
            ServerUdpSendStream { inner: &self.inner },
            ServerUdpRecvStream { inner: &self.inner },
        )
    }
}

pub struct ServerUdpSendStream<'a> {
    inner: &'a UdpSocket,
}

impl<'a> UdpWrite for ServerUdpSendStream<'a> {
    fn poll_proxy_stream_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>> {
        // self.inner.poll_send_to(cx, buf, addr.to_socket_addrs())
        todo!()
    }
}

pub struct ServerUdpRecvStream<'a> {
    inner: &'a UdpSocket,
}

use super::{
    CursoredBuffer, ExtendableFromSlice, MixAddrType, ParserError, UdpRead, UdpRelayBuffer,
    UdpWrite,
};
use futures::{ready, Future};
use quinn::*;
use std::net::SocketAddr;
use std::vec;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UdpSocket,
    task::JoinHandle,
};

use tokio::task::spawn_blocking;

pub struct ServerUdpStream {
    inner: UdpSocket,
}

impl ServerUdpStream {
    pub fn split(&mut self) -> (ServerUdpSendStream, ServerUdpRecvStream) {
        (
            ServerUdpSendStream {
                inner: &self.inner,
                addr_task: ResolveAddr::None,
            },
            ServerUdpRecvStream { inner: &self.inner },
        )
    }
}

pub struct ServerUdpSendStream<'a> {
    inner: &'a UdpSocket,
    addr_task: ResolveAddr,
}

impl<'a> UdpWrite for ServerUdpSendStream<'a> {
    fn poll_proxy_stream_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>> {
        loop {
            match self.addr_task {
                ResolveAddr::Pending(ref mut task) => {
                    match ready!(Pin::new(task).poll(cx))??.next() {
                        Some(x) => {
                            self.addr_task = ResolveAddr::Ready(x);
                        }
                        None => {
                            self.addr_task = ResolveAddr::None;
                            return Poll::Ready(Ok(0));
                        }
                    }
                }
                ResolveAddr::Ready(s_addr) => {
                    let res = self.inner.poll_send_to(cx, buf, s_addr);
                    if res.is_ready() {
                        self.addr_task = ResolveAddr::None;
                    }
                    return res;
                }
                ResolveAddr::None => {
                    use MixAddrType::*;
                    self.addr_task = match addr {
                        x @ V4(_) | x @ V6(_) => ResolveAddr::Ready(x.clone().to_socket_addrs()),
                        Hostname((name, _)) => {
                            let name = name.to_owned();
                            ResolveAddr::Pending(spawn_blocking(move || {
                                std::net::ToSocketAddrs::to_socket_addrs(&name)
                            }))
                        }
                        _ => panic!("unprecedented MixAddrType variant"),
                    };
                }
            }
        }
    }
}

enum ResolveAddr {
    Pending(JoinHandle<std::io::Result<vec::IntoIter<SocketAddr>>>),
    Ready(SocketAddr),
    None,
}

impl ResolveAddr {
    fn is_none(&self) -> bool {
        match self {
            ResolveAddr::None => true,
            _ => false,
        }
    }
}

pub struct ServerUdpRecvStream<'a> {
    inner: &'a UdpSocket,
}

impl<'a> UdpRead for ServerUdpRecvStream<'a> {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<MixAddrType>> {
        let res = self.inner.poll_recv(cx, buf);

    }
}

#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
pub use {
    client::{
        client_tcp_stream::{ClientTcpRecvStream, ClientTcpStream},
        data_transfer::relay_tcp,
    },
    tokio::net::TcpStream,
};

#[cfg(all(feature = "client", feature = "udp"))]
pub use client::{
    client_udp_stream::{Socks5UdpRecvStream, Socks5UdpSendStream, Socks5UdpStream},
    data_transfer::relay_udp,
};
#[cfg(all(feature = "client", feature = "quic"))]
use quinn::*;
#[cfg(all(feature = "client", feature = "tcp_tls"))]
use tokio_rustls::client::TlsStream;
#[cfg(feature = "server")]
mod timedout_duplex_io;

#[cfg(all(feature = "server", feature = "udp"))]
mod server_udp_stream;
#[cfg(all(feature = "server", feature = "udp"))]
pub use server_udp_stream::{ServerUdpRecvStream, ServerUdpSendStream, ServerUdpStream};

#[cfg(feature = "udp")]
mod udp;

#[cfg(feature = "udp")]
pub use udp::{
    copy_udp::copy_udp,
    trojan_udp_stream::{
        new_trojan_udp_stream, TrojanUdpRecvStream, TrojanUdpSendStream, TrojanUdpStream,
    },
    udp_relay_buffer::UdpRelayBuffer,
    udp_traits::{UdpRead, UdpWrite},
};

#[cfg(feature = "lite_tls")]
pub mod lite_tls;

mod copy_tcp;
pub use copy_tcp::copy_tcp;

mod macros;
mod mix_addr;
pub use mix_addr::MixAddrType;

use bytes::BufMut;

pub use timedout_duplex_io::{TimedoutIO, TimeoutMonitor};

use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::server::Splitable;

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "ParserError Incomplete: {:?}", _0)]
    Incomplete(&'static str),
    #[error(display = "ParserError Invalid: {:?}", _0)]
    Invalid(&'static str),
}

pub fn transmute_u16s_to_u8s(a: &[u16], b: &mut [u8]) {
    if b.len() < a.len() * 2 {
        return;
    }
    for (i, val) in a.iter().enumerate() {
        let x = val.to_be_bytes();
        b[i] = x[0];
        b[i + 1] = x[1];
    }
}

#[macro_export]
macro_rules! expect_buf_len {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Err(ParserError::Incomplete(stringify!($len)));
        }
    };
    ($buf:expr, $len:expr, $mark:expr) => {
        if $buf.len() < $len {
            // debug!("expect_buf_len {}", $mark);
            return Err(ParserError::Incomplete($mark));
        }
    };
}

pub trait CursoredBuffer {
    fn chunk(&self) -> &[u8];
    fn advance(&mut self, len: usize);
    fn remaining(&self) -> usize {
        self.chunk().len()
    }
}

impl<'a> CursoredBuffer for (&'a mut usize, &Vec<u8>) {
    fn chunk(&self) -> &[u8] {
        &self.1[*self.0..]
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.1.len() >= *self.0 + len,
            "(&'a mut usize, &Vec<u8>) was about to set a larger position than it's length"
        );
        *self.0 += len;
    }
}

pub trait VecAsReadBufExt<'a> {
    fn as_read_buf(&'a mut self, start: usize) -> ReadBuf<'a>;
}

impl<'a> VecAsReadBufExt<'a> for Vec<u8> {
    fn as_read_buf(&'a mut self, start: usize) -> ReadBuf<'a> {
        assert!(start <= self.remaining_mut());
        let dst = &mut self.chunk_mut()[start..];
        let dst = unsafe { &mut *(dst as *mut _ as *mut [std::mem::MaybeUninit<u8>]) };
        ReadBuf::uninit(dst)
    }
}

pub trait ExtendableFromSlice {
    fn extend_from_slice(&mut self, src: &[u8]);
}

impl ExtendableFromSlice for Vec<u8> {
    fn extend_from_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }
}

pub enum ConnectionRequest<TcpRequest, UdpRequest, EchoRequest> {
    TCP(TcpRequest),
    #[cfg(feature = "udp")]
    UDP(UdpRequest),
    #[cfg(feature = "quic")]
    ECHO(EchoRequest),
    _PHANTOM((TcpRequest, UdpRequest, EchoRequest)),
}

#[derive(Debug)]
pub struct BufferedRecv<T> {
    buffered_request: Option<(usize, Vec<u8>)>,
    inner: T,
}

impl<T> BufferedRecv<T> {
    pub fn new(inner: T, buffered_request: Option<(usize, Vec<u8>)>) -> Self {
        Self {
            inner,
            buffered_request,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> Splitable for BufferedRecv<T>
where
    T: Splitable,
{
    type R = BufferedRecv<T::R>;
    type W = T::W;

    fn split(self) -> (Self::R, Self::W) {
        let (r, w) = self.inner.split();
        (BufferedRecv::new(r, self.buffered_request), w)
    }
}

impl<T> AsyncRead for BufferedRecv<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.buffered_request.is_some() {
            let (index, buffered_request) = self.buffered_request.as_ref().unwrap();
            buf.put_slice(&buffered_request[*index..]);
            self.buffered_request = None;
            cx.waker().wake_by_ref(); // super important
            return Poll::Ready(Ok(()));
        }

        let reader = Pin::new(&mut self.inner);
        reader.poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for BufferedRecv<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub enum ConnectionMode {
    #[cfg(feature = "tcp_tls")]
    TcpTLS,
    #[cfg(feature = "quic")]
    Quic,
}

#[cfg(feature = "client")]
pub enum ClientServerConnection {
    #[cfg(feature = "quic")]
    Quic((SendStream, RecvStream)),
    #[cfg(feature = "tcp_tls")]
    TcpTLS(TlsStream<TcpStream>),
    #[cfg(feature = "lite_tls")]
    LiteTLS(TlsStream<TcpStream>),
}

#[derive(Debug)]
pub struct WRTuple<W, R>(pub (R, W));

impl<R, W> AsyncRead for WRTuple<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0 .1).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for WRTuple<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0 .0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0 .0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0 .0).poll_shutdown(cx)
    }
}

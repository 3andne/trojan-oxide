#[cfg(feature = "udp")]
mod udp;
#[cfg(feature = "udp")]
pub use udp::*;

#[cfg(feature = "lite_tls")]
pub mod lite_tls;

// mod copy_tcp;
// pub use copy_tcp::copy_to_tls;

mod macros;
mod mix_addr;
pub use mix_addr::*;

mod adapter;
mod either_io;
pub use adapter::*;

mod timedout_duplex_io;
pub use timedout_duplex_io::*;

use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod splitable;
pub use splitable::Splitable;

mod buffers;
pub use buffers::*;

mod forked_copy;
pub use forked_copy::*;

#[cfg(all(target_os = "linux", feature = "zio"))]
mod glommio_utils;
#[cfg(all(target_os = "linux", feature = "zio"))]
pub use glommio_utils::*;

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "ParserError Incomplete: {:?}", _0)]
    Incomplete(String),
    #[error(display = "ParserError Invalid: {:?}", _0)]
    Invalid(String),
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

    #[allow(dead_code)]
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

#[derive(Debug)]
pub struct WRTuple<W, R>(pub W, pub R);

impl<W, R> WRTuple<W, R> {
    pub fn from_wr_tuple((w, r): (W, R)) -> Self {
        Self(w, r)
    }

    pub fn from_rw_tuple((r, w): (R, W)) -> Self {
        Self(w, r)
    }
}

impl<W, R> AsyncRead for WRTuple<W, R>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.1).poll_read(cx, buf)
    }
}

impl<W, R> AsyncWrite for WRTuple<W, R>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(not(feature = "udp"))]
pub struct DummyRequest {}

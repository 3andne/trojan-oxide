use std::fmt::Debug;

use quinn::*;
use tokio::{
    io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

#[cfg(feature = "quic")]
use super::QuicStream;

pub trait SplitableToAsyncReadWrite {
    type R: AsyncRead + Unpin + Debug + Send + 'static;
    type W: AsyncWrite + Unpin + Debug + Send + 'static;

    fn split(self) -> (Self::R, Self::W);
}

#[cfg(feature = "quic")]
impl SplitableToAsyncReadWrite for QuicStream {
    type R = RecvStream;
    type W = SendStream;

    fn split(self) -> (Self::R, Self::W) {
        (self.0, self.1)
    }
}

#[cfg(feature = "quic")]
impl QuicStream {
    pub fn new(stream: (SendStream, RecvStream)) -> Self {
        return Self(stream.1, stream.0);
    }
}

impl SplitableToAsyncReadWrite for TlsStream<TcpStream> {
    type R = ReadHalf<TlsStream<TcpStream>>;
    type W = WriteHalf<TlsStream<TcpStream>>;

    fn split(self) -> (Self::R, Self::W) {
        split(self)
    }
}

use std::fmt::Debug;

use quinn::*;
use tokio::{io::{AsyncRead, AsyncWrite, split, ReadHalf, WriteHalf}, net::TcpStream};
use tokio_rustls::server::TlsStream;

use super::QuicStream;
pub trait SplitableToAsyncReadWrite {
    type R: AsyncRead + Unpin + Debug;
    type W: AsyncWrite + Unpin + Debug;

    fn split(self) -> (Self::R, Self::W);
}

impl SplitableToAsyncReadWrite for QuicStream {
    type R = RecvStream;
    type W = SendStream;

    fn split(self) -> (Self::R, Self::W) {
        (self.0, self.1)
    }
}

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

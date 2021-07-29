use std::fmt::Debug;

use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "tcp_tls")]
use tokio::{
    io::{split, ReadHalf, WriteHalf},
    net::TcpStream,
};

use crate::utils::WRTuple;

#[cfg(feature = "quic")]
use quinn::*;

pub trait Splitable {
    type R: AsyncRead + Unpin + Debug + Send + 'static;
    type W: AsyncWrite + Unpin + Debug + Send + 'static;

    fn split(self) -> (Self::R, Self::W);
}

#[cfg(feature = "quic")]
impl Splitable for (SendStream, RecvStream) {
    type R = RecvStream;
    type W = SendStream;

    fn split(self) -> (Self::R, Self::W) {
        (self.1, self.0)
    }
}

#[cfg(feature = "quic")]
impl Splitable for (RecvStream, SendStream) {
    type R = RecvStream;
    type W = SendStream;

    fn split(self) -> (Self::R, Self::W) {
        (self.0, self.1)
    }
}

#[cfg(feature = "tcp_tls")]
impl Splitable for tokio_rustls::server::TlsStream<TcpStream> {
    type R = ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>;
    type W = WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>;

    fn split(self) -> (Self::R, Self::W) {
        split(self)
    }
}

#[cfg(feature = "tcp_tls")]
impl Splitable for tokio_rustls::client::TlsStream<TcpStream> {
    type R = ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>;
    type W = WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>;

    fn split(self) -> (Self::R, Self::W) {
        split(self)
    }
}

impl<W_, R_> Splitable for WRTuple<W_, R_>
where
    R_: AsyncRead + Send + Debug + Unpin + 'static,
    W_: AsyncWrite + Send + Debug + Unpin + 'static,
{
    type R = R_;
    type W = W_;
    fn split(self) -> (Self::R, Self::W) {
        (self.0 .1, self.0 .0)
    }
}

#[cfg(feature = "quic")]
use quinn::*;
use tokio::net::TcpStream;
use tokio_rustls::{client, server};

#[cfg(feature = "quic")]
use crate::utils::{TrojanUdpStream, WRTuple};

pub trait LeaveTls {
    fn leave(self) -> TcpStream;
}

impl LeaveTls for server::TlsStream<TcpStream> {
    fn leave(self) -> TcpStream {
        self.into_inner().0
    }
}

impl LeaveTls for client::TlsStream<TcpStream> {
    fn leave(self) -> TcpStream {
        self.into_inner().0
    }
}

#[cfg(feature = "quic")]
impl<I> LeaveTls for TrojanUdpStream<I> {
    fn leave(self) -> TcpStream {
        unimplemented!()
    }
}

#[cfg(feature = "quic")]
impl LeaveTls for WRTuple<SendStream, RecvStream> {
    fn leave(self) -> TcpStream {
        unimplemented!()
    }
}

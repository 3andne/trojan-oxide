use quinn::*;
use tokio::net::TcpStream;
use tokio_rustls::{server, client};

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

impl<I> LeaveTls for TrojanUdpStream<I> {
   fn leave(self) -> TcpStream {
       unimplemented!()
   }
}

impl LeaveTls for WRTuple<RecvStream, SendStream> {
    fn leave(self) -> TcpStream {
        unimplemented!()
    }
}

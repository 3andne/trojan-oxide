mod acceptor;
mod handler;
mod listener;
mod stream_trait;
#[cfg(feature = "quic")]
mod streams;
#[cfg(feature = "tcp_tls")]
mod tcp_tls;

#[cfg(feature = "udp")]
use crate::utils::{TrojanUdpRecvStream, TrojanUdpSendStream};
pub use acceptor::TrojanAcceptor;
#[cfg(feature = "tcp_tls")]
pub use listener::tcp_tls_listener;
pub use stream_trait::SplitableToAsyncReadWrite;
#[cfg(feature = "quic")]
pub use {listener::quic_listener, streams::QuicStream};

use crate::args::Opt;
use std::net::{SocketAddr, ToSocketAddrs};
pub fn get_server_local_addr(options: &Opt) -> SocketAddr {
    ("0.0.0.0:".to_owned() + &options.proxy_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
}

#[cfg(feature = "udp")]
pub type TrojanUdpStream<W, R> = (TrojanUdpSendStream<W>, TrojanUdpRecvStream<R>);

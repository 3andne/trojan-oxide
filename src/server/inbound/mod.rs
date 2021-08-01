mod acceptor;
mod handler;
mod listener;
#[cfg(feature = "quic")]
mod quic;
#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
mod tcp_tls;

pub use acceptor::TrojanAcceptor;
#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
pub use listener::tcp_tls_listener;
#[cfg(feature = "quic")]
pub use {listener::quic_listener, quic::QuicStream};

use crate::args::Opt;
use std::net::{SocketAddr, ToSocketAddrs};
pub fn get_server_local_addr(options: &Opt) -> SocketAddr {
    ("0.0.0.0:".to_owned() + &options.proxy_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
}

// #[cfg(feature = "udp")]
// pub type TrojanUdpStream<W, R> = (TrojanUdpSendStream<W>, TrojanUdpRecvStream<R>);

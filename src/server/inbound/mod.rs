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

use std::net::{IpAddr, SocketAddr};
pub fn get_server_local_addr(proxy_port: u16) -> SocketAddr {
    SocketAddr::from((IpAddr::from([0, 0, 0, 0]), proxy_port))
}

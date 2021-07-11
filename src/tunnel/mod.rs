use crate::args::Opt;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

#[cfg(feature = "quic")]
pub mod quic;
pub mod tcp_tls;

pub fn get_server_local_addr(options: &Opt) -> SocketAddr {
    ("0.0.0.0:".to_owned() + &options.proxy_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
}

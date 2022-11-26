mod client_tcp_stream;
pub use client_tcp_stream::*;
#[cfg(feature = "udp")]
mod client_udp_stream;
#[cfg(feature = "udp")]
pub use client_udp_stream::*;
mod data_transfer;
pub use data_transfer::*;
mod client_server_connection;
pub use client_server_connection::*;

mod connection_mode;
pub use connection_mode::ConnectionMode;

mod rustls_utils;
pub use rustls_utils::get_rustls_config;

use tokio::net::TcpStream;
#[cfg(feature = "udp")]
use tokio::sync::mpsc;

#[cfg(not(feature = "udp"))]
use crate::utils::DummyRequest;

use crate::utils::{BufferedRecv, ConnectionRequest};

#[cfg(feature = "udp")]
pub type ClientConnectionRequest =
    ConnectionRequest<BufferedRecv<TcpStream>, Socks5UdpStream, mpsc::Receiver<()>>;

#[cfg(not(feature = "udp"))]
pub type ClientConnectionRequest = ConnectionRequest<ClientTcpStream, DummyRequest, DummyRequest>;

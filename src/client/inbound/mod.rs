mod http;
mod listener;
mod socks5;

use crate::{utils::ClientTcpStream, utils::ConnectionRequest};

#[cfg(feature = "udp")]
use crate::utils::Socks5UdpStream;
#[cfg(feature = "udp")]
type ClientConnectionRequest = ConnectionRequest<ClientTcpStream, Socks5UdpStream>;
#[cfg(not(feature = "udp"))]
type ClientConnectionRequest = ConnectionRequest<ClientTcpStream>;

pub use http::HttpRequest;
pub use listener::{
    accept_http_request, accept_sock5_request, user_endpoint_listener, ClientRequestAcceptResult,
};
pub use socks5::Socks5Request;

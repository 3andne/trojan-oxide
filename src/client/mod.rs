mod inbound;
mod outbound;
mod run;

pub use run::run_client;


use tokio::sync::mpsc;
use crate::{utils::ClientTcpStream, utils::ConnectionRequest};

#[cfg(feature = "udp")]
use crate::utils::Socks5UdpStream;
#[cfg(feature = "udp")]
pub type ClientConnectionRequest =
    ConnectionRequest<ClientTcpStream, Socks5UdpStream, mpsc::Receiver<()>>;

#[cfg(not(feature = "udp"))]
type ClientConnectionRequest = ConnectionRequest<ClientTcpStream, DummyRequest, DummyRequest>;

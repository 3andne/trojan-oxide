#[cfg(feature = "udp")]
mod udp;
#[cfg(feature = "udp")]
pub use udp::*;

#[cfg(feature = "lite_tls")]
pub mod lite_tls;

// mod copy_tcp;
// pub use copy_tcp::copy_to_tls;

mod macros;
mod mix_addr;
pub use mix_addr::*;

mod adapter;
mod either_io;
pub use adapter::*;

mod timedout_duplex_io;
pub use timedout_duplex_io::*;

mod buffers;
pub use buffers::*;

mod forked_copy;
pub use forked_copy::*;

mod buffered_recv;
pub use buffered_recv::BufferedRecv;

mod wr_tuple;
pub use wr_tuple::WRTuple;

mod dns_utils;
pub use dns_utils::*;

mod latency_utils;
pub use latency_utils::*;

#[cfg(all(target_os = "linux", feature = "zio"))]
mod glommio_utils;
#[cfg(all(target_os = "linux", feature = "zio"))]
pub use glommio_utils::*;

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "ParserError Incomplete: {:?}", _0)]
    Incomplete(String),
    #[error(display = "ParserError Invalid: {:?}", _0)]
    Invalid(String),
}

pub fn transmute_u16s_to_u8s(a: &[u16], b: &mut [u8]) {
    if b.len() < a.len() * 2 {
        return;
    }
    for (i, val) in a.iter().enumerate() {
        let x = val.to_be_bytes();
        b[2 * i] = x[0];
        b[2 * i + 1] = x[1];
    }
}

pub enum ConnectionRequest<TcpRequest, UdpRequest, EchoRequest> {
    TCP(TcpRequest),
    #[cfg(feature = "udp")]
    UDP(UdpRequest),
    #[cfg(feature = "quic")]
    ECHO(EchoRequest),
    _PHANTOM((TcpRequest, UdpRequest, EchoRequest)),
}

#[cfg(not(feature = "udp"))]
pub struct DummyRequest {}

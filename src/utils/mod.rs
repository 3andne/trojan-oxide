#[cfg(feature = "client")]
mod client_tcp_stream;
#[cfg(feature = "client")]
pub use client_tcp_stream::{ClientTcpRecvStream, ClientTcpStream};

#[cfg(all(feature = "client", feature = "udp"))]
mod client_udp_stream;
#[cfg(all(feature = "client", feature = "udp"))]
pub use client_udp_stream::{Socks5UdpRecvStream, Socks5UdpSendStream, Socks5UdpStream};

#[cfg(all(feature = "server", feature = "udp"))]
mod server_udp_stream;
#[cfg(all(feature = "server", feature = "udp"))]
pub use server_udp_stream::{ServerUdpRecvStream, ServerUdpSendStream, ServerUdpStream};

#[cfg(feature = "udp")]
mod trojan_udp_stream;
#[cfg(feature = "udp")]
pub use trojan_udp_stream::{new_trojan_udp_stream, TrojanUdpRecvStream, TrojanUdpSendStream};

#[cfg(feature = "udp")]
mod udp_relay_buffer;
#[cfg(feature = "udp")]
pub use udp_relay_buffer::UdpRelayBuffer;

#[cfg(feature = "udp")]
mod udp_traits;
#[cfg(feature = "udp")]
pub use udp_traits::{UdpRead, UdpWrite};
#[cfg(feature = "udp")]
mod copy_udp;
#[cfg(feature = "udp")]
pub use copy_udp::copy_udp;

mod copy_tcp;
#[cfg(feature = "client")]
mod data_transfer;
mod macros;
mod mix_addr;
use bytes::BufMut;

pub use copy_tcp::copy_tcp;

#[cfg(feature = "client")]
pub use data_transfer::relay_tcp;
#[cfg(all(feature = "udp", feature = "client"))]
pub use data_transfer::relay_udp;
pub use mix_addr::MixAddrType;

use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, ReadBuf};
#[cfg(feature = "client")]
use tokio::net::TcpStream;

#[cfg(feature = "client")]
use tokio_rustls::client::TlsStream;

#[cfg(feature = "quic")]
use quinn::*;

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "ParserError Incomplete: {:?}", _0)]
    Incomplete(&'static str),
    #[error(display = "ParserError Invalid: {:?}", _0)]
    Invalid(&'static str),
}

pub fn transmute_u16s_to_u8s(a: &[u16], b: &mut [u8]) {
    if b.len() < a.len() * 2 {
        return;
    }
    for (i, val) in a.iter().enumerate() {
        let x = val.to_be_bytes();
        b[i] = x[0];
        b[i + 1] = x[1];
    }
}

#[macro_export]
macro_rules! expect_buf_len {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Err(ParserError::Incomplete(stringify!($len)));
        }
    };
    ($buf:expr, $len:expr, $mark:expr) => {
        if $buf.len() < $len {
            debug!("expect_buf_len {}", $mark);
            return Err(ParserError::Incomplete);
        }
    };
}

pub trait CursoredBuffer {
    fn chunk(&self) -> &[u8];
    fn advance(&mut self, len: usize);
    fn remaining(&self) -> usize {
        self.chunk().len()
    }
}

impl<'a> CursoredBuffer for (&'a mut usize, &Vec<u8>) {
    fn chunk(&self) -> &[u8] {
        &self.1[*self.0..]
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.1.len() >= *self.0 + len,
            "(&'a mut usize, &Vec<u8>) was about to set a larger position than it's length"
        );
        *self.0 += len;
    }
}

pub trait VecAsReadBufExt<'a> {
    fn as_read_buf(&'a mut self) -> ReadBuf<'a>;
}

impl<'a> VecAsReadBufExt<'a> for Vec<u8> {
    fn as_read_buf(&'a mut self) -> ReadBuf<'a> {
        let dst = self.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [std::mem::MaybeUninit<u8>]) };
        ReadBuf::uninit(dst)
    }
}

pub trait ExtendableFromSlice {
    fn extend_from_slice(&mut self, src: &[u8]);
}

impl ExtendableFromSlice for Vec<u8> {
    fn extend_from_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }
}

#[cfg(feature = "udp")]
pub enum ConnectionRequest<TcpRequest, UdpRequest> {
    TCP(TcpRequest),
    UDP(UdpRequest),
    #[cfg(feature = "quic")]
    ECHO(TcpRequest),
}

#[cfg(not(feature = "udp"))]
pub enum ConnectionRequest<TcpRequest> {
    TCP(TcpRequest),
    #[cfg(feature = "quic")]
    ECHO(TcpRequest),
}

#[derive(Debug)]
pub struct BufferedRecv<T> {
    buffered_request: Option<(usize, Vec<u8>)>,
    inner: T,
}

impl<T> BufferedRecv<T> {
    pub fn new(inner: T, buffered_request: Option<(usize, Vec<u8>)>) -> Self {
        Self {
            inner,
            buffered_request,
        }
    }
}

impl<T> AsyncRead for BufferedRecv<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.buffered_request.is_some() {
            let (index, buffered_request) = self.buffered_request.as_ref().unwrap();
            buf.put_slice(&buffered_request[*index..]);
            self.buffered_request = None;
            return Poll::Ready(Ok(()));
        }

        let reader = Pin::new(&mut self.inner);
        reader.poll_read(cx, buf)
    }
}

#[derive(Debug, Clone)]
pub enum ConnectionMode {
    #[cfg(feature = "tcp_tls")]
    TcpTLS,
    #[cfg(feature = "quic")]
    Quic,
}

#[cfg(feature = "client")]
pub enum ClientServerConnection {
    #[cfg(feature = "quic")]
    Quic((SendStream, RecvStream)),
    #[cfg(feature = "tcp_tls")]
    TcpTLS(TlsStream<TcpStream>),
}

mod data_transfer;
mod client_tcp_stream;
mod client_udp_stream;
mod copy;
mod mix_addr;
mod server_udp_stream;
mod trojan_udp_stream;
pub mod debug_reader_writer;

use bytes::BufMut;
pub use client_tcp_stream::{ClientTcpRecvStream, ClientTcpStream};
pub use client_udp_stream::{Socks5UdpRecvStream, Socks5UdpSendStream, Socks5UdpStream};
pub use copy::copy_udp;
pub use mix_addr::MixAddrType;
pub use server_udp_stream::{ServerUdpRecvStream, ServerUdpSendStream, ServerUdpStream};
pub use trojan_udp_stream::{new_trojan_udp_stream, TrojanUdpRecvStream, TrojanUdpSendStream};
pub use data_transfer::{relay_tcp, relay_udp};

use quinn::*;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

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

#[derive(Debug)]
pub struct UdpRelayBuffer {
    cursor: usize,
    inner: Vec<u8>,
}

impl<'a> UdpRelayBuffer {
    fn new() -> Self {
        let buf = Vec::with_capacity(2048);
        Self {
            cursor: 0,
            inner: buf,
        }
    }

    fn as_read_buf(&'a mut self) -> ReadBuf<'a> {
        self.inner.as_read_buf()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.inner.advance_mut(cnt);
    }

    unsafe fn reset(&mut self) {
        self.inner.set_len(0);
        self.cursor = 0;
    }

    fn has_remaining(&self) -> bool {
        self.cursor < self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn pump(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let data_len = self.remaining();
        for i in 0..data_len {
            self.inner[i] = self.inner[i + self.cursor];
        }
        unsafe {
            self.inner.set_len(data_len);
        }
        self.cursor = 0;
    }
}

impl<'a> CursoredBuffer for UdpRelayBuffer {
    fn chunk(&self) -> &[u8] {
        &self.inner[self.cursor..]
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.inner.len() >= self.cursor + len,
            "UdpRelayBuffer was about to set a larger position({}+{}) than it's length({})",
            self.cursor,
            len,
            self.inner.len()
        );
        self.cursor += len;
    }
}

impl Deref for UdpRelayBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.chunk()
    }
}

pub trait UdpRead {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<crate::utils::MixAddrType>>;
}

pub trait UdpWrite {
    fn poll_proxy_stream_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>>;
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

impl ExtendableFromSlice for UdpRelayBuffer {
    fn extend_from_slice(&mut self, src: &[u8]) {
        self.inner.extend_from_slice(src);
    }
}

pub enum ConnectionRequest<TcpRequest, UdpRequest> {
    TCP(TcpRequest),
    UDP(UdpRequest),
    ECHO(TcpRequest),
}

#[derive(Debug)]
pub struct BufferedRecv<T> {
    buffered_request: Option<Vec<u8>>,
    inner: T,
}

impl<T> BufferedRecv<T> {
    pub fn new(inner: T, buffered_request: Option<Vec<u8>>) -> Self {
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
            let buffered_request = self.buffered_request.as_ref().unwrap();
            buf.put_slice(&buffered_request);
            self.buffered_request = None;
            return Poll::Ready(Ok(()));
        }

        let reader = Pin::new(&mut self.inner);
        reader.poll_read(cx, buf)
    }
}

#[derive(Debug, Clone)]
pub enum ConnectionMode {
    TcpTLS,
    Quic,
}

pub enum ClientServerConnection {
    Quic((SendStream, RecvStream)),
    TcpTLS(TlsStream<TcpStream>),
}

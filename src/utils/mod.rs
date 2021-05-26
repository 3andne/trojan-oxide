mod client_tcp_stream;
mod client_udp_stream;
mod copy;
mod mix_addr;

use bytes::BufMut;
pub use client_tcp_stream::{ClientTcpRecvStream, ClientTcpStream};
pub use client_udp_stream::{Socks5UdpRecvStream, Socks5UdpSendStream, Socks5UdpStream};
pub use mix_addr::MixAddrType;
use tokio::io::ReadBuf;

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "Incomplete")]
    Incomplete,
    #[error(display = "Invalid")]
    Invalid,
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
            return Err(ParserError::Incomplete);
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
    fn as_bytes(&self) -> &[u8];
    fn advance(&mut self, len: usize);
}

impl CursoredBuffer for std::io::Cursor<&[u8]> {
    fn as_bytes(&self) -> &[u8] {
        *self.get_ref()
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.get_ref().len() as u64 >= self.position() + len as u64,
            "Cursor<&[u8]> was about to set a larger position than it's length"
        );
        self.set_position(self.position() + len as u64);
    }
}

impl<'a> CursoredBuffer for tokio::io::ReadBuf<'a> {
    fn as_bytes(&self) -> &[u8] {
        self.filled()
    }

    fn advance(&mut self, len: usize) {
        self.advance(len);
    }
}

impl<'a> CursoredBuffer for (&'a mut usize, &Vec<u8>) {
    fn as_bytes(&self) -> &[u8] {
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

pub struct UdpRelayBuffer {
    cursor: usize,
    buf: Vec<u8>,
}

impl<'a> UdpRelayBuffer {
    fn new() -> Self {
        let buf = Vec::with_capacity(2048);
        Self { cursor: 0, buf }
    }

    fn as_read_buf(&'a mut self) -> ReadBuf<'a> {
        let dst = &mut self.buf.chunk_mut()[self.cursor..];
        let dst = unsafe { &mut *(dst as *mut _ as *mut [std::mem::MaybeUninit<u8>]) };
        ReadBuf::uninit(dst)
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.buf.advance_mut(cnt);
    }

    unsafe fn reset(&mut self) {
        self.buf.set_len(0);
        self.cursor = 0;
    }

    fn has_remaining(&self) -> bool {
        self.cursor < self.buf.len()
    }
}

impl<'a> CursoredBuffer for UdpRelayBuffer {
    fn as_bytes(&self) -> &[u8] {
        &self.buf[self.cursor..]
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.buf.len() >= self.cursor + len,
            "UdpRelayBuffer was about to set a larger position than it's length"
        );
        self.cursor += len;
    }
}

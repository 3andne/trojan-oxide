mod client_tcp_stream;
mod client_udp_stream;
mod mix_addr;

pub use client_tcp_stream::{ClientTcpRecvStream, ClientTcpStream};
pub use client_udp_stream::{ClientUdpRecvStream, ClientUdpSendStream, ClientUdpStream};
pub use mix_addr::MixAddrType;

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

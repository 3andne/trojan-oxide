use super::lite_tls_stream::Direction;
use crate::{expect_buf_len, utils::ParserError};
use anyhow::Result;
use std::{
    cmp::min,
    ops::{Deref, DerefMut},
};
// use tokio::io::{AsyncReadExt, AsyncWriteExt};

// #[cfg(feature = "debug_info")]
// use tracing::debug;

// pub(super) enum TlsVersion {
//     Tls12,
//     Tls13,
// }

#[derive(Debug)]
pub struct TlsRelayBuffer {
    inner: Vec<u8>,
    /// read cursor
    cursor: usize,
}

impl Deref for TlsRelayBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TlsRelayBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

fn extract_len(buf: &[u8]) -> usize {
    buf[0] as usize * 256 + buf[1] as usize
}

// pub(super) enum Expecting {
//     Num(usize),
//     Packet(u8),
// }

#[derive(Debug, Clone, Copy)]
pub(super) enum Seen0x17 {
    None,
    FromInbound,
    FromOutbound,
    BothDirections,
}

pub(super) enum LeaveTlsSide {
    Active,
    Passive,
}

impl Seen0x17 {
    fn witness(&mut self, dir: Direction) {
        use Direction::*;
        use Seen0x17::*;
        *self = match (*self, dir) {
            (None, Inbound) => FromInbound,
            (None, Outbound) => FromOutbound,
            (FromInbound, Outbound) | (FromOutbound, Inbound) => BothDirections,
            (BothDirections, _) => unreachable!(),
            _ => return,
        };
    }

    fn is_complete(&self) -> bool {
        match self {
            &Seen0x17::BothDirections => true,
            _ => false,
        }
    }
}

// impl Expecting {
//     fn is_expected(&self) -> bool {
//         match self {
//             Expecting::Num(l) => *l == 0,
//             Expecting::Packet(_) => false,
//         }
//     }
// }

impl TlsRelayBuffer {
    pub fn new() -> Self {
        Self {
            inner: Vec::with_capacity(2048),
            cursor: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn reset(&mut self) {
        unsafe {
            self.inner.set_len(0);
        }
        self.cursor = 0;
    }

    pub fn checked_packets(&self) -> &[u8] {
        if self.cursor < self.inner.len() {
            &self.inner[..self.cursor]
        } else {
            &self.inner
        }
    }

    pub fn pop_checked_packets(&mut self) {
        let new_len = self.inner.len() - min(self.cursor, self.inner.len());
        for i in 0..new_len {
            self.inner[i] = self.inner[self.cursor + i];
        }

        self.cursor -= self.inner.len() - new_len;

        unsafe {
            self.inner.set_len(new_len);
        }
    }

    pub fn check_client_hello(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(self.inner, 5, "client hello incomplete[1]");
        if &self.inner[..3] != &[0x16, 0x03, 0x01] {
            // Not tls 1.2/1.3
            return Err(ParserError::Invalid("not tls 1.2/1.3[1]".into()));
        }
        self.cursor = 5 + extract_len(&self.inner[3..]);
        if self.cursor != self.inner.len() {
            // Not tls 1.2/1.3
            return Err(ParserError::Invalid("not tls 1.2/1.3[2]".into()));
        }
        Ok(())
    }

    pub(super) fn check_tls_packet(&mut self) -> Result<u8, ParserError> {
        expect_buf_len!(
            self.inner,
            self.cursor + 5,
            "packet 0x16 (or sth) incomplete[1]"
        );
        let packet_type = self.inner[self.cursor];
        self.cursor += 5 + extract_len(&self.inner[self.cursor + 3..]);
        expect_buf_len!(
            self.inner,
            self.cursor,
            "packet 0x16 (or sth) incomplete[2]"
        );
        Ok(packet_type)
    }

    // pub(super) async fn check_tls_packets<R>(
    //     &mut self,
    //     mut expecting: Expecting,
    //     reader: &mut R,
    // ) -> Result<()>
    // where
    //     R: AsyncReadExt + Unpin,
    // {
    //     while !expecting.is_expected() {
    //         match self.check_tls_packet() {
    //             Ok(p_ty) => match &mut expecting {
    //                 Expecting::Num(l) => *l -= 1,
    //                 Expecting::Packet(t) => {
    //                     if p_ty == *t {
    //                         break;
    //                     }
    //                 }
    //             },
    //             Err(ParserError::Incomplete(_)) => {
    //                 // let's try to read the last encrypted packet
    //                 if reader.read_buf(self.deref_mut()).await? == 0 {
    //                     return Err(eof_err("EOF on Parsing[4]"));
    //                 }
    //             }
    //             Err(e @ ParserError::Invalid(_)) => {
    //                 return Err(Error::new(e))
    //                     .with_context(|| anyhow!("tls 1.2 full handshake last step"));
    //             }
    //         }
    //     }

    //     return Ok(());
    // }

    // pub async fn write_checked_packets<W>(&mut self, writer: &mut W) -> Result<()>
    // where
    //     W: AsyncWriteExt + Unpin,
    // {
    //     #[cfg(feature = "debug_info")]
    //     debug!("[LC2]buf before pop: {:?}", self);
    //     // relay till last byte
    //     if writer.write(&self.checked_packets()).await? == 0 {
    //         return Err(eof_err("EOF on Parsing[3]"));
    //     }
    //     writer.flush().await?;
    //     self.pop_checked_packets();
    //     #[cfg(feature = "debug_info")]
    //     debug!("[LC2]buf after pop: {:?}", self);
    //     // then we are safe to leave TLS channel
    //     Ok(())
    // }

    pub(super) fn find_first_0x17(
        &mut self,
        seen_0x17: &mut Seen0x17,
        dir: Direction,
    ) -> Result<LeaveTlsSide, ParserError> {
        loop {
            expect_buf_len!(self.inner, self.cursor + 1, "find 0x17 incomplete");
            match self.inner[self.cursor] {
                0x17 => {
                    seen_0x17.witness(dir);
                    if seen_0x17.is_complete() {
                        return Ok(LeaveTlsSide::Active);
                    } else {
                        self.check_tls_packet()?;
                    }
                }
                0xff => {
                    return Ok(LeaveTlsSide::Passive);
                }
                0x14 | 0x15 | 0x16 => {
                    self.check_tls_packet()?;
                }
                _ => {
                    return Err(ParserError::Invalid("unexpected tls packet type".into()));
                }
            }
        }
    }
}

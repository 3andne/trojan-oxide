use super::{
    error::eof_err,
    lite_tls_stream::{Direction, LiteTlsEndpointSide},
};
use crate::{expect_buf_len, utils::ParserError};
use anyhow::{anyhow, Context, Error, Result};
use std::{
    cmp::min,
    ops::{Deref, DerefMut},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "debug_info")]
use tracing::debug;

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
    FromInbound(LeaveTlsMode),
    FromOutbound(LeaveTlsMode),
    BothDirections(LeaveTlsMode),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum LeaveTlsMode {
    Active,
    Passive,
}

impl Seen0x17 {
    fn witness(&mut self, dir: Direction, side: LiteTlsEndpointSide) {
        use Direction::*;
        use LeaveTlsMode::*;
        use LiteTlsEndpointSide::*;
        use Seen0x17::*;
        *self = match (*self, dir) {
            (None, Inbound) => FromInbound(match side {
                ClientSide => Passive,
                ServerSide => Active,
            }),
            (None, Outbound) => FromOutbound(match side {
                ServerSide => Passive,
                ClientSide => Active,
            }),
            (FromInbound(mode), Outbound) | (FromOutbound(mode), Inbound) => BothDirections(mode),
            (BothDirections(_), _) => unreachable!(),
            _ => return,
        };
    }

    fn is_complete(&self) -> bool {
        match self {
            &Seen0x17::BothDirections(_) => true,
            _ => false,
        }
    }
}

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

    fn peek_tls_type(&self) -> Result<u8, ParserError> {
        expect_buf_len!(self.inner, self.cursor + 5, "packet incomplete[1]");
        let packet_type = self.inner[self.cursor];
        let cursor = self.cursor + 5 + extract_len(&self.inner[self.cursor + 3..]);
        expect_buf_len!(self.inner, cursor, "packet 0x16 (or sth) incomplete[2]");
        Ok(packet_type)
    }

    pub(super) fn check_tls_packet(&mut self) -> Result<u8, ParserError> {
        expect_buf_len!(self.inner, self.cursor + 5, "packet incomplete[1]");
        let packet_type = self.inner[self.cursor];
        self.cursor += 5 + extract_len(&self.inner[self.cursor + 3..]);
        expect_buf_len!(
            self.inner,
            self.cursor,
            "packet 0x16 (or sth) incomplete[2]"
        );
        Ok(packet_type)
    }

    pub(super) fn find_first_0x17(
        &mut self,
        seen_0x17: &mut Seen0x17,
        dir: Direction,
        side: LiteTlsEndpointSide,
    ) -> Result<LeaveTlsMode, ParserError> {
        loop {
            expect_buf_len!(self.inner, self.cursor + 1, "find 0x17 incomplete");
            match self.inner[self.cursor] {
                0x17 => {
                    self.check_tls_packet()?;
                    #[cfg(feature = "debug_info")]
                    debug!("found 0x17, already seen: {:?}", seen_0x17);
                    seen_0x17.witness(dir, side);
                    #[cfg(feature = "debug_info")]
                    debug!("now seen 0x17: {:?}", seen_0x17);
                    if seen_0x17.is_complete() {
                        return Ok(match seen_0x17 {
                            Seen0x17::BothDirections(mode) => *mode,
                            _ => unreachable!(),
                        });
                    } else {
                        #[cfg(feature = "debug_info")]
                        debug!("lite-tls first 0x17");
                    }
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

    pub(super) async fn relay_until_0xff<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        loop {
            match self.peek_tls_type() {
                Ok(p_ty) => {
                    if p_ty == 0xff {
                        self.flush_checked(writer).await?;
                        self.check_tls_packet()?;
                        self.pop_checked_packets();
                        return Ok(());
                    } else {
                        self.check_tls_packet()?;
                    }
                }
                Err(ParserError::Incomplete(_)) => {
                    self.flush_checked(writer).await?;
                    if reader.read_buf(self.deref_mut()).await? == 0 {
                        return Err(eof_err("EOF on Parsing[]"));
                    }
                }
                Err(e @ ParserError::Invalid(_)) => {
                    return Err(Error::new(e))
                        .with_context(|| anyhow!("tls 1.2 full handshake last step"));
                }
            }
        }
    }

    pub(super) async fn flush_checked<W>(&mut self, writer: &mut W) -> Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        if self.checked_packets().len() > 0 {
            if writer.write(self.checked_packets()).await? == 0 {
                return Err(eof_err("EOF on Parsing[]"));
            }
            writer.flush().await?;
            self.pop_checked_packets();
        }
        Ok(())
    }
}

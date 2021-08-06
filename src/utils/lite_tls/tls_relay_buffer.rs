use super::lite_tls_stream::Direction;
use crate::{
    expect_buf_len,
    utils::{lite_tls::error::eof_err, ParserError},
};
use anyhow::{anyhow, Context, Error, Result};
use std::{
    cmp::min,
    ops::{Deref, DerefMut},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) enum TlsVersion {
    Tls12,
    Tls13,
}

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

    pub fn check_type_0x14(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(self.inner, self.cursor + 6, "packet 0x14 incomplete");
        if &self.inner[self.cursor..self.cursor + 6] != &[0x14, 0x03, 0x03, 0, 0x01, 0x01] {
            Err(ParserError::Invalid("packet 0x14 invalid".into()))
        } else {
            self.cursor += 6;
            Ok(())
        }
    }

    pub fn check_tls_packet(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(
            self.inner,
            self.cursor + 5,
            "packet 0x16 (or sth) incomplete[1]"
        );
        self.cursor += 5 + extract_len(&self.inner[self.cursor + 3..]);
        expect_buf_len!(
            self.inner,
            self.cursor,
            "packet 0x16 (or sth) incomplete[2]"
        );
        Ok(())
    }

    pub(super) async fn relay_tls_packets<R, W>(
        &mut self,
        mut num_of_packets: usize,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        while num_of_packets > 0 {
            match self.check_tls_packet() {
                Ok(_) => num_of_packets -= 1,
                Err(ParserError::Incomplete(_)) => {
                    // let's try to read the last encrypted packet
                    if reader.read_buf(self.deref_mut()).await? == 0 {
                        return Err(eof_err("EOF on Parsing[4]"));
                    }
                }
                Err(e @ ParserError::Invalid(_)) => {
                    return Err(Error::new(e))
                        .with_context(|| anyhow!("tls 1.2 full handshake last step"));
                }
            }
        }
        // relay till last byte
        if writer.write(&self.checked_packets()).await? == 0 {
            return Err(eof_err("EOF on Parsing[3]"));
        }
        writer.flush().await?;
        self.pop_checked_packets();
        #[cfg(feature = "debug_info")]
        debug!(
            "[LC2][{}]out buf after pop: {:?}",
            packet_id, self.outbound_buf
        );
        // then we are safe to leave TLS channel
        return Ok(());
    }

    pub(super) fn find_last_change_cipher_spec(
        &mut self,
        seen_ccs: &mut usize,
        dir: Direction,
    ) -> Result<TlsVersion, ParserError> {
        loop {
            expect_buf_len!(
                self.inner,
                self.cursor + 1,
                "find change cipher spec incomplete"
            );
            match self.inner[self.cursor] {
                0x14 => {
                    self.check_type_0x14()?;
                    match (*seen_ccs, dir) {
                        (1, Direction::Inbound) => {
                            return Ok(TlsVersion::Tls13);
                        }
                        (0, Direction::Inbound) => {
                            return Ok(TlsVersion::Tls12);
                        }
                        (0, Direction::Outbound) => {
                            *seen_ccs += 1;
                        }
                        _ => unreachable!(),
                    }
                }
                0x16 | 0x17 | 0x15 => {
                    // problematic
                    self.check_tls_packet()?;
                }
                _ => {
                    return Err(ParserError::Invalid("unexpected tls packet type".into()));
                }
            }
        }
    }
}

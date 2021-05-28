use crate::{
    expect_buf_len,
    utils::{MixAddrType, ParserError},
};
use anyhow::Result;
use quinn::*;
use tokio::io::AsyncReadExt;
use tracing::*;

pub mod trojan;

pub const HASH_LEN: usize = 56;

#[derive(Default, Debug)]
pub struct Target<'a> {
    host: MixAddrType,
    cursor: usize,
    password_hash: &'a [u8],
    buf: Vec<u8>,
    is_udp: bool,
}

impl<'a> Target<'a> {
    pub fn new(password_hash: &[u8]) -> Target {
        Target {
            password_hash,
            ..Default::default()
        }
    }

    fn verify(&mut self) -> Result<(), ParserError> {
        if self.buf.len() < HASH_LEN {
            return Err(ParserError::Incomplete);
        }

        if &self.buf[..HASH_LEN] == self.password_hash {
            self.cursor = HASH_LEN + 2;
            Ok(())
        } else {
            Err(ParserError::Invalid)
        }
    }

    fn set_host_and_port(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(self.buf, HASH_LEN + 5); // HASH + \r\n + cmd(2 bytes) + host_len(1 byte, only valid when address is hostname)
        self.is_udp = match self.buf[HASH_LEN + 2] {
            0x01 => false,
            0x03 => true,
            _ => return Err(ParserError::Invalid),
        };
        self.cursor += 1;
        self.host = MixAddrType::from_encoded(&mut (&mut self.cursor, &self.buf))?;
        Ok(())
    }

    /// ```not_rust
    /// +-----------------------+---------+----------------+---------+----------+
    /// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
    /// +-----------------------+---------+----------------+---------+----------+
    /// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
    /// +-----------------------+---------+----------------+---------+----------+
    ///
    /// where Trojan Request is a SOCKS5-like request:
    ///
    /// +-----+------+----------+----------+
    /// | CMD | ATYP | DST.ADDR | DST.PORT |
    /// +-----+------+----------+----------+
    /// |  1  |  1   | Variable |    2     |
    /// +-----+------+----------+----------+
    ///
    /// where:
    ///
    /// o  CMD
    ///     o  CONNECT X'01'
    ///     o  UDP ASSOCIATE X'03'
    /// o  ATYP address type of following address
    ///     o  IP V4 address: X'01'
    ///     o  DOMAINNAME: X'03'
    ///     o  IP V6 address: X'04'
    /// o  DST.ADDR desired destination address
    /// o  DST.PORT desired destination port in network octet order
    /// ```
    pub async fn accept(&mut self, in_read: &mut RecvStream) -> Result<(), ParserError> {
        loop {
            let read = in_read
                .read_buf(&mut self.buf)
                .await
                .map_err(|_| ParserError::Invalid)?;
            if read != 0 {
                match self.parse() {
                    Err(ParserError::Invalid) => {
                        debug!("invalid");
                        return Err(ParserError::Invalid);
                    }
                    Err(ParserError::Incomplete) => {
                        debug!("Incomplete");
                        continue;
                    }
                    Ok(()) => {
                        debug!("Ok");
                        break;
                    }
                }
            } else {
                return Err(ParserError::Invalid);
            }
        }
        Ok(())
    }

    pub fn parse(&mut self) -> Result<(), ParserError> {
        debug!(
            "parse begin, cursor {}, buffer({}): {:?}",
            self.cursor,
            self.buf.len(),
            &self.buf[self.cursor..]
        );
        if self.cursor == 0 {
            self.verify()?;
            debug!("verified");
        }

        if self.host.is_none() {
            self.set_host_and_port()?;
        }

        debug!("target: {:?}", self);

        expect_buf_len!(self.buf, self.cursor + 2);
        if &self.buf[self.cursor..self.cursor + 2] == b"\r\n" {
            self.cursor += 2;
            Ok(())
        } else {
            Err(ParserError::Invalid)
        }
    }
}

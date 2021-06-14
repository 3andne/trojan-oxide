use crate::{
    expect_buf_len,
    utils::{
        new_trojan_udp_stream, ConnectionRequest, MixAddrType, ParserError, TrojanUdpRecvStream,
        TrojanUdpSendStream,
    },
};
use anyhow::Result;
use quinn::*;
use tokio::io::AsyncReadExt;
use tracing::*;

pub mod trojan;

pub const HASH_LEN: usize = 56;

pub type QuicStream = (SendStream, RecvStream);
pub type TrojanUdpStream = (TrojanUdpSendStream, TrojanUdpRecvStream);

#[derive(Default, Debug)]
pub struct Target<'a> {
    host: MixAddrType,
    cursor: usize,
    password_hash: &'a [u8],
    buf: Vec<u8>,
    cmd_code: u8,
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
            return Err(ParserError::Incomplete(
                "Target::verify self.buf.len() < HASH_LEN",
            ));
        }

        if &self.buf[..HASH_LEN] == self.password_hash {
            self.cursor = HASH_LEN + 2;
            Ok(())
        } else {
            Err(ParserError::Invalid("Target::verify hash invalid"))
        }
    }

    fn set_host_and_port(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(self.buf, HASH_LEN + 5); // HASH + \r\n + cmd(2 bytes) + host_len(1 byte, only valid when address is hostname)

        unsafe {
            // This is so buggy
            self.cursor = HASH_LEN + 3;
        }

        self.cmd_code = self.buf[HASH_LEN + 2];
        match self.cmd_code {
            0x01 | 0x03 => {
                self.host = MixAddrType::from_encoded(&mut (&mut self.cursor, &self.buf))?;
            }
            0xff => (),
            _ => {
                return Err(ParserError::Invalid(
                    "Target::verify invalid connection type",
                ))
            }
        };
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
    ///     o  PROBING X'FF'
    /// o  ATYP address type of following address
    ///     o  IP V4 address: X'01'
    ///     o  DOMAINNAME: X'03'
    ///     o  IP V6 address: X'04'
    /// o  DST.ADDR desired destination address
    /// o  DST.PORT desired destination port in network octet order
    /// ```
    pub async fn accept(
        &mut self,
        mut inbound: QuicStream,
    ) -> Result<ConnectionRequest<QuicStream, TrojanUdpStream>, ParserError> {
        loop {
            let read = inbound
                .1
                .read_buf(&mut self.buf)
                .await
                .map_err(|_| ParserError::Invalid("Target::accept failed to read"))?;
            if read != 0 {
                match self.parse() {
                    Err(err @ ParserError::Invalid(_)) => {
                        error!("Target::accept failed: {:?}", err);
                        return Err(err);
                    }
                    Err(err @ ParserError::Incomplete(_)) => {
                        debug!("Target::accept failed: {:?}", err);
                        continue;
                    }
                    Ok(()) => {
                        debug!("Ok");
                        break;
                    }
                }
            } else {
                return Err(ParserError::Invalid("Target::accept unexpected EOF"));
            }
        }
        use ConnectionRequest::*;
        let buffered_request = if self.buf.len() == self.cursor {
            None
        } else {
            Some(Vec::from(&self.buf[self.cursor..]))
        };
        Ok(match self.cmd_code {
            0x03 => UDP(new_trojan_udp_stream(
                inbound.0,
                inbound.1,
                buffered_request,
            )),
            0x01 => TCP(inbound),
            0xff => ECHO(inbound),
            _ => unreachable!(),
        })
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
            Err(ParserError::Invalid("Target::accept expecting CRLF"))
        }
    }
}

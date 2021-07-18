use super::SplitableToAsyncReadWrite;
use crate::{
    expect_buf_len,
    protocol::HASH_LEN,
    simd::trojan_password_compare,
    server::outbound::fallback,
    utils::{BufferedRecv, ConnectionRequest, MixAddrType, ParserError},
};
use anyhow::Result;
use futures::TryFutureExt;
use std::{fmt::Debug, sync::Arc};
use tokio::io::AsyncReadExt;
use tracing::*;
#[cfg(feature = "udp")]
use {super::TrojanUdpStream, crate::utils::new_trojan_udp_stream};

#[cfg(feature = "udp")]
type ServerConnectionRequest<I> = ConnectionRequest<
    (
        <I as SplitableToAsyncReadWrite>::W,
        BufferedRecv<<I as SplitableToAsyncReadWrite>::R>,
    ),
    TrojanUdpStream<<I as SplitableToAsyncReadWrite>::W, <I as SplitableToAsyncReadWrite>::R>,
>;
#[cfg(not(feature = "udp"))]
type ServerConnectionRequest<I> = ConnectionRequest<(
    <I as SplitableToAsyncReadWrite>::W,
    BufferedRecv<<I as SplitableToAsyncReadWrite>::R>,
)>;
#[derive(Default, Debug)]
pub struct TrojanAcceptor<'a> {
    pub host: MixAddrType,
    cursor: usize,
    password_hash: &'a [u8],
    buf: Vec<u8>,
    cmd_code: u8,
    fallback_port: Arc<String>,
}

impl<'a> TrojanAcceptor<'a> {
    pub fn new(password_hash: &[u8], fallback_port: Arc<String>) -> TrojanAcceptor {
        TrojanAcceptor {
            password_hash,
            fallback_port,
            buf: Vec::with_capacity(128),
            ..Default::default()
        }
    }

    fn verify(&mut self) -> Result<(), ParserError> {
        if self.buf.len() < HASH_LEN {
            return Err(ParserError::Incomplete(
                "Target::verify self.buf.len() < HASH_LEN",
            ));
        }

        if trojan_password_compare(&self.buf[..HASH_LEN], self.password_hash) {
            self.cursor = HASH_LEN + 2;
            Ok(())
        } else {
            Err(ParserError::Invalid("Target::verify hash invalid"))
        }
    }

    fn set_host_and_port(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(
            self.buf,
            HASH_LEN + 5,
            "TrojanAcceptor::set_host_and_port cmd"
        ); // HASH + \r\n + cmd(2 bytes) + host_len(1 byte, only valid when address is hostname)

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
    pub async fn accept<I: SplitableToAsyncReadWrite + Debug + Unpin>(
        &mut self,
        inbound: I,
    ) -> Result<ServerConnectionRequest<I>, ParserError> {
        let (mut read_half, write_half) = inbound.split();
        loop {
            let read = read_half
                .read_buf(&mut self.buf)
                .await
                .map_err(|_| ParserError::Invalid("Target::accept failed to read"))?;
            if read != 0 {
                match self.parse() {
                    Err(err @ ParserError::Invalid(_)) => {
                        error!("Target::accept failed: {:#}", err);
                        let mut buf = Vec::new();
                        std::mem::swap(&mut buf, &mut self.buf);
                        tokio::spawn(
                            fallback(buf, self.fallback_port.clone(), read_half, write_half)
                                .unwrap_or_else(|e| {
                                    error!("connection to fallback failed {:#}", e)
                                }),
                        );
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
                return Err(ParserError::Incomplete("Target::accept EOF"));
            }
        }
        use ConnectionRequest::*;
        let buffered_request = if self.buf.len() == self.cursor {
            None
        } else {
            Some((self.cursor, std::mem::take(&mut self.buf)))
        };

        Ok(match self.cmd_code {
            #[cfg(feature = "udp")]
            0x03 => UDP(new_trojan_udp_stream(
                write_half,
                read_half,
                buffered_request,
            )),
            0x01 => TCP((write_half, BufferedRecv::new(read_half, buffered_request))),
            #[cfg(feature = "quic")]
            0xff => ECHO((write_half, BufferedRecv::new(read_half, buffered_request))),
            _ => unreachable!(),
        })
    }

    pub fn parse(&mut self) -> Result<(), ParserError> {
        #[cfg(feature = "debug_info")]
        debug!(
            "parse begin, cursor {}, buffer({}): {:?}",
            self.cursor,
            self.buf.len(),
            &self.buf[self.cursor..]
        );
        if self.cursor == 0 {
            self.verify()?;
            #[cfg(feature = "debug_info")]
            debug!("verified");
        }

        if self.host.is_none() {
            self.set_host_and_port()?;
        }

        #[cfg(feature = "debug_info")]
        debug!("target: {:?}", self);

        expect_buf_len!(self.buf, self.cursor + 2, "TrojanAcceptor::parse CRLF");

        if &self.buf[self.cursor..self.cursor + 2] == b"\r\n" {
            self.cursor += 2;
            Ok(())
        } else {
            Err(ParserError::Invalid("Target::accept expecting CRLF"))
        }
    }
}

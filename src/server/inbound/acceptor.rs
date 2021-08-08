#[cfg(not(feature = "udp"))]
use crate::utils::DummyRequest;
#[cfg(feature = "udp")]
use crate::utils::{new_trojan_udp_stream, TrojanUdpStream};
use crate::{
    expect_buf_len,
    protocol::{
        ECHO_REQUEST_CMD, HASH_LEN, LITE_TLS_REQUEST_CMD, TCP_REQUEST_CMD, UDP_REQUEST_CMD,
    },
    server::{outbound::fallback, utils::TcpOption},
    utils::{BufferedRecv, CommonParserError, ConnectionRequest, MixAddrType, ParserError},
};
use anyhow::Result;
use futures::TryFutureExt;
use std::{fmt::Debug, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::*;
#[cfg(feature = "udp")]
type ServerConnectionRequest<I> =
    ConnectionRequest<TcpOption<BufferedRecv<I>>, TrojanUdpStream<I>, BufferedRecv<I>>;
#[cfg(not(feature = "udp"))]
#[allow(type_alias_bounds)]
type ServerConnectionRequest<I: SplitableToAsyncReadWrite> =
    ConnectionRequest<(I::W, BufferedRecv<I::R>), DummyRequest, (I::W, BufferedRecv<I::R>)>;
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
            buf: Vec::with_capacity(1024),
            ..Default::default()
        }
    }

    fn verify(&mut self) -> Result<(), CommonParserError> {
        if self.buf.len() < HASH_LEN {
            return Err(CommonParserError::Incomplete(
                "Target::verify self.buf.len() < HASH_LEN".into(),
            ));
        }

        if &self.buf[..HASH_LEN] == self.password_hash {
            self.cursor = HASH_LEN + 2;
            Ok(())
        } else {
            Err(CommonParserError::Invalid(
                "Target::verify hash invalid".into(),
            ))
        }
    }

    fn set_host_and_port(&mut self) -> Result<(), CommonParserError> {
        expect_buf_len!(
            self.buf,
            HASH_LEN + 5,
            "TrojanAcceptor::set_host_and_port cmd"
        ); // HASH + \r\n + cmd(2 bytes) + host_len(1 byte, only valid when address is hostname)

        // unsafe: This is so buggy
        self.cursor = HASH_LEN + 3;

        self.cmd_code = self.buf[HASH_LEN + 2];
        match self.cmd_code {
            TCP_REQUEST_CMD | UDP_REQUEST_CMD | LITE_TLS_REQUEST_CMD => {
                self.host = MixAddrType::from_encoded(&mut (&mut self.cursor, &self.buf))?;
            }
            ECHO_REQUEST_CMD => (),
            _ => {
                return Err(CommonParserError::Invalid(
                    "Target::verify invalid connection type".into(),
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
    pub async fn accept<I>(
        &mut self,
        mut inbound: I,
    ) -> Result<ServerConnectionRequest<I>, CommonParserError>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // let (mut read_half, write_half) = inbound.split();
        loop {
            let read = inbound
                .read_buf(&mut self.buf)
                .await
                .map_err(|_| CommonParserError::Invalid("Target::accept failed to read".into()))?;
            if read != 0 {
                match self.parse() {
                    Err(err @ CommonParserError::Invalid(_)) => {
                        error!("Target::accept failed: {:#}", err);
                        let mut buf = Vec::new();
                        std::mem::swap(&mut buf, &mut self.buf);
                        tokio::spawn(
                            fallback(buf, self.fallback_port.clone(), inbound).unwrap_or_else(
                                |e| error!("connection to fallback failed {:#}", e),
                            ),
                        );
                        return Err(err);
                    }
                    Err(err @ CommonParserError::Incomplete(_)) => {
                        debug!("Target::accept failed: {:?}", err);
                        continue;
                    }
                    Ok(()) => {
                        debug!("Ok");
                        break;
                    }
                }
            } else {
                return Err(CommonParserError::Incomplete("Target::accept EOF".into()));
            }
        }
        use ConnectionRequest::*;
        let buffered_request = if self.buf.len() == self.cursor {
            None
        } else {
            Some((self.cursor, std::mem::take(&mut self.buf)))
        };

        use TcpOption::*;
        match self.cmd_code {
            #[cfg(feature = "udp")]
            UDP_REQUEST_CMD => Ok(UDP(new_trojan_udp_stream(inbound, buffered_request))),
            #[cfg(not(feature = "udp"))]
            UDP_REQUEST_CMD => Err(CommonParserError::Invalid(
                "udp functionality not included".into(),
            )),
            TCP_REQUEST_CMD => Ok(TCP(TLS(BufferedRecv::new(inbound, buffered_request)))),
            LITE_TLS_REQUEST_CMD => Ok(TCP(LiteTLS(BufferedRecv::new(inbound, buffered_request)))),
            #[cfg(feature = "quic")]
            ECHO_REQUEST_CMD => Ok(ECHO(BufferedRecv::new(inbound, buffered_request))),
            _ => unreachable!(),
        }
    }

    pub fn parse(&mut self) -> Result<(), CommonParserError> {
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
            Err(CommonParserError::Invalid(
                "Target::accept expecting CRLF".into(),
            ))
        }
    }
}

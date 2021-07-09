use std::{fmt::Debug, io::Cursor, pin::Pin, sync::Arc};

use crate::{
    expect_buf_len,
    utils::{new_trojan_udp_stream, ConnectionRequest, MixAddrType, ParserError, TrojanUdpStream},
};
use anyhow::Result;
use quinn::*;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    select,
};
use tracing::*;

pub mod trojan;
pub mod trojan_stream;

pub const HASH_LEN: usize = 56;
#[derive(Debug)]
pub struct QuicStream(RecvStream, SendStream);

impl QuicStream {
    pub fn new(stream: (SendStream, RecvStream)) -> Self {
        return Self(stream.1, stream.0);
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.1).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.1).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.1).poll_shutdown(cx)
    }
}

#[derive(Default, Debug)]
pub struct Target<'a> {
    host: MixAddrType,
    cursor: usize,
    password_hash: &'a [u8],
    buf: Vec<u8>,
    cmd_code: u8,
    fallback_port: Arc<String>,
}

// use trojan_stream::SplitableToAsyncReadWrite;
impl<'a> Target<'a> {
    pub fn new(password_hash: &[u8], fallback_port: Arc<String>) -> Target {
        Target {
            password_hash,
            fallback_port,
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
    pub async fn accept<I>(
        &mut self,
        mut inbound: I,
    ) -> Result<ConnectionRequest<I, TrojanUdpStream<I>>, ParserError>
    where
        I: AsyncRead + AsyncWrite + Debug + Unpin + Send + 'static,
    {
        loop {
            let read = inbound
                .read_buf(&mut self.buf)
                .await
                .map_err(|_| ParserError::Invalid("Target::accept failed to read"))?;
            if read != 0 {
                match self.parse() {
                    Err(err @ ParserError::Invalid(_)) => {
                        error!("Target::accept failed: {:?}", err);
                        let mut buf = Vec::new();
                        std::mem::swap(&mut buf, &mut self.buf);
                        tokio::spawn(fallback(buf, self.fallback_port.clone(), inbound));
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
            0x03 => UDP(new_trojan_udp_stream(inbound, buffered_request)),
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

async fn fallback<I: AsyncRead + AsyncWrite + Unpin>(
    buf: Vec<u8>,
    fallback_port: Arc<String>,
    mut inbound: I,
) -> Result<()> {
    let mut outbound = TcpStream::connect("127.0.0.1:".to_owned() + fallback_port.as_str()).await?;
    outbound.write_buf(&mut Cursor::new(&buf)).await?;

    let res = tokio::io::copy_bidirectional(&mut outbound, &mut inbound).await;
    debug!("tcp relaying end, {:?}", res);
    Ok(())
}

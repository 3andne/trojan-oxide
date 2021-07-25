use crate::{
    expect_buf_len,
    utils::{ClientTcpStream, ParserError},
};
use anyhow::{Error, Result};
use std::{
    cmp::min,
    io::ErrorKind,
    ops::{Deref, DerefMut},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    select,
};
use tokio_rustls::client::TlsStream;

struct TlsRelayBuffer {
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
    fn reset(&mut self) {
        unsafe {
            self.inner.set_len(0);
        }
        self.cursor = 0;
    }

    fn checked_packets(&self) -> &[u8] {
        if self.cursor < self.inner.len() {
            &self.inner[..self.cursor]
        } else {
            &self.inner
        }
    }

    fn pop_checked_packets(&mut self) {
        let new_len = self.inner.len() - min(self.cursor, self.inner.len());
        for i in 0..new_len {
            self.inner[i] = self.inner[self.cursor + i];
        }

        unsafe {
            self.inner.set_len(new_len);
        }
        self.cursor -= self.inner.len() - new_len;
    }

    fn check_client_hello(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(self.inner, 5, "client hello incomplete[1]");
        if &self.inner[..3] != &[0x16, 0x03, 0x01] {
            // Not tls 1.2/1.3
            return Err(ParserError::Invalid("not tls 1.2/1.3[1]"));
        }
        self.cursor = 5 + extract_len(&self.inner[3..]);
        if self.cursor != self.inner.len() {
            // Not tls 1.2/1.3
            return Err(ParserError::Invalid("not tls 1.2/1.3[2]"));
        }
        Ok(())
    }

    fn check_type_0x14(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(self.inner, self.cursor + 6, "packet 0x14 incomplete");
        if &self.inner[self.cursor..self.cursor + 6] != &[0x14, 0x03, 0x03, 0, 0x01, 0x01] {
            Err(ParserError::Invalid("packet 0x14 invalid"))
        } else {
            self.cursor += 6;
            Ok(())
        }
    }

    fn check_type_0x16(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(
            self.inner,
            self.cursor + 5,
            "packet 0x16 (or sth) incomplete[1]"
        );
        self.cursor += 5 + extract_len(&self.inner[self.cursor..]);
        expect_buf_len!(
            self.inner,
            self.cursor,
            "packet 0x16 (or sth) incomplete[2]"
        );
        Ok(())
    }

    fn find_change_cipher_spec(&mut self) -> Result<(), ParserError> {
        loop {
            expect_buf_len!(
                self.inner,
                self.cursor + 1,
                "find change cipher spec incomplete"
            );
            match self.inner[self.cursor] {
                0x14 => {
                    return self.check_type_0x14();
                }
                0x16 | 0x17 | 0x15 => {
                    // problematic
                    self.check_type_0x16()?;
                }
                _ => {
                    return Err(ParserError::Invalid("unexpected tls packet type"));
                }
            }
        }
    }
}

pub struct ClientLiteStream {
    inner: TlsStream<TcpStream>,
    inbound_buf: TlsRelayBuffer,
    outbound_buf: TlsRelayBuffer,
    change_cipher_recieved: usize,
}

fn EofErr(msg: &str) -> Error {
    Error::new(std::io::Error::new(ErrorKind::UnexpectedEof, msg))
}

impl ClientLiteStream {
    /// if Ok(_) is returned, then quit TLS channel, relay the remaining
    /// packets through TCP
    ///
    /// if Err(Invalid) is returned, then relay the remaining packets
    /// through tls
    ///
    /// if Err(other) is returned, the stream is probably non-recoverable
    /// just quit
    pub async fn handshake(&mut self, inbound: &mut ClientTcpStream) -> Result<()> {
        if inbound.http_request_extension.is_some() {
            return Err(Error::new(ParserError::Invalid("HTTP Request")));
        }

        // Client Hello
        if inbound.inner.read(&mut self.inbound_buf).await? == 0 {
            return Err(EofErr("EOF on Client Hello"));
        }
        self.inbound_buf
            .check_client_hello()
            // doesn't look like a tls stream, leave it alone
            .map_err(|x| {
                Error::new(ParserError::Invalid("check_client_hello invalid")).context(x)
            })?;

        // relay packet
        self.inner.write(&self.inbound_buf).await?;
        self.inbound_buf.reset();

        #[derive(Debug, Clone, Copy)]
        enum Direction {
            Inbound,
            Outbound,
        }

        loop {
            let (res, dir) = select! {
                res = inbound.inner.read(&mut self.inbound_buf) => {
                    (res?, Direction::Inbound)
                }
                res = self.inner.read(&mut self.outbound_buf) => {
                    (res?, Direction::Outbound)
                }
            };

            if res == 0 {
                return Err(EofErr("EOF on Parsing[1]"));
            }

            match (
                match dir {
                    Direction::Inbound => &mut self.inbound_buf,
                    Direction::Outbound => &mut self.outbound_buf,
                }
                .find_change_cipher_spec(),
                dir,
                self.change_cipher_recieved,
            ) {
                (_, _, x) if x > 1 => unreachable!(),
                (Ok(_), Direction::Inbound, 0) => {
                    // TLS 1.2 full handshake: client send
                    // CCS first
                    self.change_cipher_recieved = 1;
                }
                (Ok(_), Direction::Inbound, 1) => {
                    // TLS 1.2 with resumption or TLS 1.3
                    self.change_cipher_recieved = 2;
                    // relay everything till the end of CCS
                    // there might be some 0x17 packets left
                    if self.inner.write(self.inbound_buf.checked_packets()).await? == 0 {
                        return Err(EofErr("EOF on Parsing[2]"));
                    }
                    self.inbound_buf.pop_checked_packets();

                    // wait for server's response
                    // this is not part of the TLS specification,
                    // but we have to do this to correctly
                    // leave TLS channel.
                    if self.inner.read(&mut self.outbound_buf).await? == 0 {
                        return Err(EofErr("EOF on Parsing[7]"));
                    }

                    // check: x must be 6 and the rsp should
                    // be [0x14, 0x03, 0x03, 0, 0x01, 0x01]
                    // (change_cipher_spec)
                    match self.outbound_buf.check_type_0x14() {
                        Ok(_) => {
                            // clear this, since it's not part of
                            // TLS.
                            self.outbound_buf.reset();
                            // Then it's safe for us to leave TLS
                            return Ok(());
                        }
                        Err(_) => {
                            // Something's wrong, which I'm not
                            // sure what it is currently.
                            todo!()
                        }
                    }
                }
                (Ok(_), Direction::Outbound, 0) => {
                    // TLS 1.2 with resumption or TLS 1.3
                    // server send CCS first
                    self.change_cipher_recieved = 1;
                }
                (Ok(_), Direction::Outbound, 1) => {
                    // TLS 1.2 full handshake
                    self.change_cipher_recieved = 2;
                    loop {
                        match self.outbound_buf.check_type_0x16() {
                            Ok(_) => {
                                // relay till last byte
                                if inbound.inner.write(&self.outbound_buf).await? == 0 {
                                    return Err(EofErr("EOF on Parsing[3]"));
                                }
                                self.outbound_buf.reset();
                                // then we are safe to leave TLS channel
                                return Ok(());
                            }
                            Err(ParserError::Incomplete(_)) => {
                                // let's try to read the last encrypted packet
                                if self.inner.read(&mut self.outbound_buf).await? == 0 {
                                    return Err(EofErr("EOF on Parsing[4]"));
                                }
                            }
                            Err(e @ ParserError::Invalid(_)) => {
                                return Err(
                                    Error::new(e).context("tls 1.2 full handshake last step")
                                );
                            }
                        }
                    }
                }
                (Err(ParserError::Incomplete(_)), _, _) => {
                    // relay pending packets
                }
                (Err(e @ ParserError::Invalid(_)), dir, seen) => {
                    return Err(Error::new(e).context(format!("{:?}, {}", dir, seen)));
                }
                _ => unreachable!(),
            }

            // relay pending bytes
            match dir {
                Direction::Inbound => {
                    if self.inner.write(self.inbound_buf.checked_packets()).await? == 0 {
                        return Err(EofErr("EOF on Parsing[5]"));
                    }
                    self.inbound_buf.pop_checked_packets();
                }
                Direction::Outbound => {
                    if inbound
                        .inner
                        .write(self.outbound_buf.checked_packets())
                        .await?
                        == 0
                    {
                        return Err(EofErr("EOF on Parsing[6]"));
                    }
                    self.outbound_buf.pop_checked_packets();
                }
            }
        }
    }
}

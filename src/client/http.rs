use crate::{
    proxy::ConnectionRequest,
    server::HASH_LEN,
    utils::{MixAddrType, ParserError},
};
use anyhow::{Error, Result};
// use futures::future;
// use std::io::IoSlice;
// use std::pin::Pin;
use std::sync::Arc;
use tokio::io::*;
use tokio::net::TcpStream;
use tracing::*;

pub struct HttpRequest {
    is_https: bool,
    addr: MixAddrType,
    cursor: usize,
}

const HEADER0: &'static [u8] = b"GET / HTTP/1.1\r\nHost: ";
const HEADER1: &'static [u8] = b"\r\nConnection: keep-alive\r\n\r\n";

impl HttpRequest {
    pub fn new() -> Self {
        Self {
            is_https: false,
            addr: MixAddrType::None,
            cursor: 0,
        }
    }

    pub fn addr(&self) -> MixAddrType {
        self.addr
    }

    fn set_stream_type(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        if buf.len() < 4 {
            return Err(ParserError::Incomplete);
        }

        if &buf[..4] == b"GET " {
            self.is_https = false;
            self.cursor = 4;
            return Ok(());
        }

        if buf.len() < 8 {
            return Err(ParserError::Incomplete);
        }

        if &buf[..8] == b"CONNECT " {
            self.is_https = true;
            self.cursor = 8;
            return Ok(());
        }

        return Err(ParserError::Invalid);
    }

    fn set_host(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        debug!("set_host entered");
        while self.cursor < buf.len() && buf[self.cursor] == b' ' {
            self.cursor += 1;
        }
        if !self.is_https {
            if self.cursor + 7 < buf.len() {
                if &buf[self.cursor..self.cursor + 7].to_ascii_lowercase()[..] == b"http://" {
                    self.cursor += 7;
                }
            } else {
                return Err(ParserError::Incomplete);
            }
        }

        let start = self.cursor;
        let mut end = start;
        while end < buf.len() && buf[end] != b' ' && buf[end] != b'/' {
            end += 1;
        }

        if end == buf.len() {
            return Err(ParserError::Incomplete);
        }

        self.addr = MixAddrType::from_http_header(self.is_https, &buf[start..end])?;
        return Ok(());
    }

    fn parse(&mut self, buf: &mut Vec<u8>) -> Result<(), ParserError> {
        debug!("parsing: {:?}", String::from_utf8(buf.clone()));
        if self.cursor == 0 {
            self.set_stream_type(buf)?;
        }

        debug!("stream is https: {}", self.is_https);

        if self.addr.is_none() {
            self.set_host(buf)?;
        }

        debug!("stream target host: {:?}", self.addr);

        // `integrity` check
        if &buf[buf.len() - 4..] == b"\r\n\r\n" {
            debug!("integrity test passed");
            return Ok(());
        }

        for i in 0..4 {
            buf[i] = buf[buf.len() - 4 + i];
        }

        unsafe {
            buf.set_len(4);
        }
        Err(ParserError::Incomplete)
    }

    pub async fn accept(&mut self, inbound: &mut TcpStream) -> Result<ConnectionRequest> {
        let mut buffer = Vec::with_capacity(200);
        loop {
            let read = inbound.read_buf(&mut buffer).await?;
            if read != 0 {
                match self.parse(&mut buffer) {
                    Ok(_) => {
                        debug!("http request parsed");
                        break;
                    }
                    Err(ParserError::Invalid) => {
                        return Err(Error::new(ParserError::Invalid));
                    }
                    _ => (),
                }
            } else {
                return Err(Error::new(ParserError::Invalid));
            }
        }

        if self.is_https {
            inbound
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            inbound.flush().await?;
            debug!("https packet 0 sent");
        }

        Ok(ConnectionRequest::TCP)
    }

    pub async fn send_packet0<A>(&self, outbound: &mut A, password_hash: Arc<String>) -> Result<()>
    where
        A: AsyncWrite + Unpin + ?Sized,
    {
        let mut buf = Vec::with_capacity(HASH_LEN + 2 + 1 + self.addr.encoded_len() + 2);
        buf.extend_from_slice(password_hash.as_bytes());
        buf.extend_from_slice(&[b'\r', b'\n', 1]);
        self.addr.write_buf(&mut buf);
        buf.extend_from_slice(&[b'\r', b'\n']);
        outbound.write_all(&buf).await?;
        // not using the following code because of quinn's bug.
        // let packet0 = [
        //     IoSlice::new(password_hash.as_bytes()),
        //     IoSlice::new(&command0[..command0_len]),
        //     IoSlice::new(self.host.as_bytes()),
        //     IoSlice::new(&port_arr),
        //     IoSlice::new(&[b'\r', b'\n']),
        // ];
        // let mut writer = Pin::new(outbound);
        // future::poll_fn(|cx| writer.as_mut().poll_write_vectored(cx, &packet0[..]))
        //     .await
        //     .map_err(|e| Box::new(e))?;

        if !self.is_https {
            let http_p0 = [HEADER0, self.addr.host_repr().as_bytes(), HEADER1].concat();
            outbound.write_all(&http_p0).await?;
            //     let bufs = [
            //         IoSlice::new(HEADER0),
            //         IoSlice::new(self.host_raw.as_bytes()),
            //         IoSlice::new(HEADER1),
            //     ];

            //     future::poll_fn(|cx| writer.as_mut().poll_write_vectored(cx, &bufs[..]))
            //         .await
            //         .map_err(|e| Box::new(e))?;

            //     debug!("http packet 0 sent");
        }
        // writer.flush().await.map_err(|e| Box::new(e))?;
        outbound.flush().await?;
        debug!("trojan packet 0 sent");

        Ok(())
    }
}

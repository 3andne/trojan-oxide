use crate::{
    client::utils::ClientTcpStream,
    utils::ConnectionRequest,
    utils::{MixAddrType, ParserError},
};

use anyhow::{Error, Result};
use futures::Future;
// use futures::future;
// use std::io::IoSlice;
// use std::pin::Pin;
use tokio::io::*;
use tokio::net::TcpStream;
use tracing::*;

use crate::client::utils::ClientConnectionRequest;

use super::{listener::RequestFromClient, ClientRequestAcceptResult};

pub struct HttpRequest {
    is_https: bool,
    addr: MixAddrType,
    cursor: usize,
    inbound: Option<TcpStream>,
}

const HEADER0: &'static [u8] = b"GET / HTTP/1.1\r\nHost: ";
const HEADER1: &'static [u8] = b"\r\nConnection: keep-alive\r\n\r\n";

impl HttpRequest {
    fn set_stream_type(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        if buf.len() < 4 {
            return Err(ParserError::Incomplete(
                "HttpRequest::set_stream_type".into(),
            ));
        }

        if &buf[..4] == b"GET " {
            self.is_https = false;
            self.cursor = 4;
            return Ok(());
        }

        if buf.len() < 8 {
            return Err(ParserError::Incomplete(
                "HttpRequest::set_stream_type".into(),
            ));
        }

        if &buf[..8] == b"CONNECT " {
            self.is_https = true;
            self.cursor = 8;
            return Ok(());
        }

        return Err(ParserError::Invalid("HttpRequest::set_stream_type".into()));
    }

    fn set_host(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        #[cfg(feature = "debug_info")]
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
                return Err(ParserError::Incomplete("HttpRequest::set_host".into()));
            }
        }

        let start = self.cursor;
        let mut end = start;
        while end < buf.len() && buf[end] != b' ' && buf[end] != b'/' {
            end += 1;
        }

        if end == buf.len() {
            return Err(ParserError::Incomplete("HttpRequest::set_host".into()));
        }

        self.addr = MixAddrType::from_http_header(self.is_https, &buf[start..end])?;
        return Ok(());
    }

    fn parse(&mut self, buf: &mut Vec<u8>) -> Result<(), ParserError> {
        #[cfg(feature = "debug_info")]
        debug!("parsing: {:?}", String::from_utf8(buf.clone()));
        if self.cursor == 0 {
            self.set_stream_type(buf)?;
        }

        #[cfg(feature = "debug_info")]
        debug!("stream is https: {}", self.is_https);

        if self.addr.is_none() {
            match self.set_host(buf) {
                Ok(_) => {
                    #[cfg(feature = "debug_info")]
                    debug!("stream target host: {:?}", self.addr);
                }
                err @ Err(_) => {
                    #[cfg(feature = "debug_info")]
                    debug!("stream target host err: {:?}", err);
                    return err;
                }
            }
        }

        // `integrity` check
        if &buf[buf.len() - 4..] == b"\r\n\r\n" {
            #[cfg(feature = "debug_info")]
            debug!("integrity test passed");
            return Ok(());
        }

        for i in 0..4 {
            buf[i] = buf[buf.len() - 4 + i];
        }

        unsafe {
            buf.set_len(4);
        }
        Err(ParserError::Incomplete("HttpRequest::parse".into()))
    }

    async fn impl_accept(&mut self) -> Result<ClientConnectionRequest> {
        let mut buffer = Vec::with_capacity(200);
        let mut inbound = self.inbound.take().unwrap();
        loop {
            let read = inbound.read_buf(&mut buffer).await?;
            if read != 0 {
                match self.parse(&mut buffer) {
                    Ok(_) => {
                        #[cfg(feature = "debug_info")]
                        debug!("http request parsed");
                        break;
                    }
                    Err(e @ ParserError::Invalid(_)) => {
                        return Err(Error::new(e));
                    }
                    _ => (),
                }
            } else {
                return Err(Error::new(ParserError::Invalid(
                    "HttpRequest::accept unable to accept before EOF".into(),
                )));
            }
        }

        let http_p0 = if self.is_https {
            inbound
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            inbound.flush().await?;
            debug!("https packet 0 sent");
            None
        } else {
            Some([HEADER0, self.addr.host_repr().as_bytes(), HEADER1].concat())
            //     let bufs = [
            //         IoSlice::new(HEADER0),
            //         IoSlice::new(self.host_raw.as_bytes()),
            //         IoSlice::new(HEADER1),
            //     ];

            //     future::poll_fn(|cx| writer.as_mut().poll_write_vectored(cx, &bufs[..]))
            //         .await
            //         .map_err(|e| Box::new(e))?;

            //     debug!("http packet 0 sent");
        };

        Ok(ConnectionRequest::TCP(ClientTcpStream {
            inner: inbound,
            http_request_extension: http_p0,
        }))
    }
}

impl RequestFromClient for HttpRequest {
    type Accepting<'a> = impl Future<Output = ClientRequestAcceptResult> + Send;

    fn accept<'a>(mut self) -> Self::Accepting<'a> {
        async move { Ok::<_, Error>((self.impl_accept().await?, self.addr)) }
    }

    fn new(inbound: TcpStream) -> Self {
        Self {
            is_https: false,
            addr: MixAddrType::None,
            cursor: 0,
            inbound: Some(inbound),
        }
    }
}

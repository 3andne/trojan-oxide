use crate::{args::Opt, quic_tunnel::*};
use anyhow::{Error, Result};
use futures::future;
use quinn::*;
use std::io::IoSlice;
use std::pin::Pin;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot};
use tokio::{io::*, select};
use tracing::*;

struct Target {
    is_https: bool,
    host: String,
    cursor: usize,
}

#[derive(Debug, err_derive::Error)]
enum ParserError {
    #[error(display = "Incomplete")]
    Incomplete,
    #[error(display = "Invalid")]
    Invalid,
}

const HEADER0: &'static [u8] = b"GET / HTTP/1.1\r\nHost: ";
const HEADER1: &'static [u8] = b"\r\nConnection: keep-alive\r\n\r\n";

impl Target {
    fn new() -> Self {
        Self {
            is_https: false,
            host: String::new(),
            cursor: 0,
        }
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

        if end < buf.len() {
            self.host =
                String::from_utf8(buf[start..end].to_vec()).map_err(|_| ParserError::Invalid)?;
            if !self.is_https {
                let mut has_port = false;
                for i in self.host[self.host.len() - 6..].as_bytes() {
                    if *i == b':' {
                        has_port = true;
                        break;
                    }
                }
                if !has_port {
                    self.host += ":80";
                }
            }
            return Ok(());
        }

        return Err(ParserError::Incomplete);
    }

    fn parse(&mut self, buf: &mut Vec<u8>) -> Result<(), ParserError> {
        trace!("parsing: {:?}", String::from_utf8(buf.clone()));
        if self.cursor == 0 {
            self.set_stream_type(buf)?;
        }

        trace!("stream is https: {}", self.is_https);

        if self.host.len() == 0 {
            self.set_host(buf)?;
        }

        trace!("stream target host: {}", self.host);

        // `integrity` check
        if &buf[buf.len() - 4..] == b"\r\n\r\n" {
            trace!("integrity test passed");
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

    async fn accept(&mut self, inbound: &mut TcpStream) -> Result<()> {
        let mut buffer = Vec::with_capacity(200);
        loop {
            let read = inbound.read_buf(&mut buffer).await?;
            if read != 0 {
                match self.parse(&mut buffer) {
                    Ok(_) => {
                        trace!("stream parsed");
                        return Ok(());
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
    }

    async fn write_packet0<A, B>(&self, inbound: &mut A, outbound: &mut B) -> Result<()>
    where
        A: AsyncWrite + Unpin + ?Sized,
        B: AsyncWrite + Unpin + ?Sized,
    {
        if self.is_https {
            inbound
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            trace!("https packet 0 sent");
        } else {
            let bufs = [
                IoSlice::new(HEADER0),
                IoSlice::new(self.host.as_bytes()),
                IoSlice::new(HEADER1),
            ];

            let mut writer = Pin::new(outbound);
            future::poll_fn(|cx| writer.as_mut().poll_write_vectored(cx, &bufs[..]))
                .await
                .map_err(|e| Box::new(e))?;

            writer.flush().await.map_err(|e| Box::new(e))?;
            trace!("http packet 0 sent");
        }
        Ok(())
    }
}

async fn handle(
    mut stream: TcpStream,
    mut upper_shutdown: broadcast::Receiver<()>,
    tunnel: (SendStream, RecvStream),
) -> Result<()> {
    let mut target = Target::new();
    target.accept(&mut stream).await?;

    // let mut outbound = TcpStream::connect(target.host.clone()).await?;

    trace!("outbound connected");

    let (mut out_write, mut out_read) = tunnel;
    target.write_packet0(&mut stream, &mut out_write).await?;

    let (mut in_read, mut in_write) = stream.split();

    trace!("start relaying");
    select! {
        _ = tokio::io::copy(&mut out_read, &mut in_write) => {
            trace!("relaying upload end");
        },
        _ = tokio::io::copy(&mut in_read, &mut out_write) => {
            trace!("relaying download end");
        },
        _ = upper_shutdown.recv() => {
            trace!("shutdown signal received");
        },
    }
    Ok(())
}

async fn run(
    listener: TcpListener,
    mut upper_shutdown: oneshot::Receiver<()>,
    options: Opt,
) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    let mut quic_tx = quic_tunnel_tx(&options).await?;
    loop {
        match upper_shutdown.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => (),
            _ => {
                break;
            }
        }
        let (stream, _) = listener.accept().await?;
        trace!("accepted tcp: {:?}", stream);
        let tunnel = match quic_tx.open_bi().await {
            Ok(t) => t,
            Err(e) => {
                trace!("{}", e);
                quic_tx = quic_tunnel_tx(&options).await?;
                quic_tx.open_bi().await?
            }
        };
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let _ = handle(stream, shutdown_rx, tunnel).await;
        });
    }
    Ok(())
}

pub async fn start_server(
    listener: TcpListener,
    ctrl_c: impl std::future::Future,
    options: Opt,
) -> Result<()> {
    info!("server-start");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    select! {
        _ = ctrl_c => {
            info!("ctrl-c");
        }
        _ = run(listener, shutdown_rx, options) => {}
    }

    drop(shutdown_tx);
    Ok(())
}

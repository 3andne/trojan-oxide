use anyhow::{Error, Result};
use futures::future;
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
}

async fn handle(
    mut stream: TcpStream,
    mut upper_shutdown1: broadcast::Receiver<()>,
    mut upper_shutdown2: broadcast::Receiver<()>,
) -> Result<()> {
    let mut buffer = Vec::with_capacity(500);
    let mut target = Target::new();
    loop {
        let read = stream.read_buf(&mut buffer).await?;
        if read != 0 {
            match target.parse(&mut buffer) {
                Ok(_) => {
                    trace!("stream parsed");
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

    let mut outbound = TcpStream::connect(target.host.clone()).await?;

    trace!("outbound connected");

    if target.is_https {
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        trace!("https packet 0 sent");
    } else {
        let bufs = [
            IoSlice::new(HEADER0),
            IoSlice::new(target.host.as_bytes()),
            IoSlice::new(HEADER1),
        ];

        let mut writer = Pin::new(&mut outbound);
        future::poll_fn(|cx| writer.as_mut().poll_write_vectored(cx, &bufs[..]))
            .await
            .map_err(|e| Box::new(e))?;

        outbound.flush().await.map_err(|e| Box::new(e))?;
        trace!("http packet 0 sent");
    }

    let (mut in_read, mut in_write) = stream.into_split();
    let (mut out_read, mut out_write) = outbound.into_split();

    tokio::spawn(async move {
        trace!("relaying 1");
        select! {
            _ = tokio::io::copy(&mut in_read, &mut out_write) => {},
            _ = upper_shutdown1.recv() => {},
        }
        trace!("relaying 1 end");
    });

    trace!("relaying 2");

    select! {
        _ = tokio::io::copy(&mut out_read, &mut in_write) => {},
        _ = upper_shutdown2.recv() => {},
    }

    trace!("relaying 2 end");

    Ok(())
}

async fn run(listener: TcpListener, mut upper_shutdown: oneshot::Receiver<()>) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);
    loop {
        match upper_shutdown.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => (),
            _ => {
                break;
            }
        }
        let (stream, _) = listener.accept().await?;
        trace!("accepted tcp: {:?}", stream);
        let shutdown_rx1 = shutdown_tx.subscribe();
        let shutdown_rx2 = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let _ = handle(stream, shutdown_rx1, shutdown_rx2).await;
        });
    }
    Ok(())
}

pub async fn start_server(listener: TcpListener, ctrl_c: impl std::future::Future) -> Result<()> {
    info!("server-start");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    select! {
        _ = ctrl_c => {
            info!("ctrl-c");
        }
        _ = run(listener, shutdown_rx) => {}
    }

    drop(shutdown_tx);
    Ok(())
}

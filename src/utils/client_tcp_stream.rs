use std::{pin::Pin, task::Poll};
use tokio::{io::AsyncReadExt, net::{
    tcp::{ReadHalf, WriteHalf},
    TcpStream,
}};
use std::net::SocketAddr;
use tokio::io::{AsyncRead};

pub struct ClientTcpStream {
    pub http_request_extension: Option<Vec<u8>>,
    pub inner: TcpStream,
}

pub struct ClientTcpRecvStream<'a> {
    http_request_extension: &'a Option<Vec<u8>>,
    inner: ReadHalf<'a>,
}

impl ClientTcpStream {
    pub fn split(&mut self) -> (ClientTcpRecvStream, WriteHalf) {
        let (read, write) = self.inner.split();
        (
            ClientTcpRecvStream {
                http_request_extension: &self.http_request_extension,
                inner: read,
            },
            write,
        )
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

impl<'a> AsyncRead for ClientTcpRecvStream<'a> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.http_request_extension.is_some() {
            let http_packet0 = self.http_request_extension.as_ref().unwrap();
            buf.put_slice(&http_packet0);
            self.http_request_extension = &None;
        }

        let reader = Pin::new(&mut self.inner);
        // reader.read(buf)
        return reader.poll_read(cx, buf);
    }
}

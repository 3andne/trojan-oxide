use crate::{utils::BufferedRecv};
use tokio::net::{
    tcp::{ReadHalf, WriteHalf},
    TcpStream,
};

pub struct ClientTcpStream {
    pub http_request_extension: Option<Vec<u8>>,
    pub inner: TcpStream,
}

pub type ClientTcpRecvStream<'a> = BufferedRecv<ReadHalf<'a>>;

impl ClientTcpStream {
    pub fn split(&mut self) -> (ClientTcpRecvStream, WriteHalf) {
        let (read, write) = self.inner.split();
        (
            ClientTcpRecvStream::new(read, self.http_request_extension.take().map(|v| (0, v))),
            write,
        )
    }
}

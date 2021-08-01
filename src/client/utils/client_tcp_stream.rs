use crate::{utils::BufferedRecv, utils::Splitable};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};

pub struct ClientTcpStream {
    pub http_request_extension: Option<Vec<u8>>,
    pub inner: TcpStream,
}

pub type ClientTcpRecvStream = BufferedRecv<OwnedReadHalf>;

impl Splitable for ClientTcpStream {
    type R = ClientTcpRecvStream;
    type W = OwnedWriteHalf;

    fn split(mut self) -> (Self::R, Self::W) {
        let (read, write) = self.inner.split();
        (
            ClientTcpRecvStream::new(read, self.http_request_extension.take().map(|v| (0, v))),
            write,
        )
    }
}

use futures::ready;
use std::net::SocketAddr;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

pub struct ClientUdpStream {
    server_udp_socket: UdpSocket,
    client_udp_addr: Option<SocketAddr>,
}

pub struct ClientUdpRecvStream<'a> {
    server_udp_socket: &'a UdpSocket,
    client_udp_addr: Option<SocketAddr>,
    addr_tx: Option<oneshot::Sender<SocketAddr>>,
}

pub struct ClientUdpSendStream<'a> {
    server_udp_socket: &'a UdpSocket,
    client_udp_addr: Option<SocketAddr>,
    addr_rx: Option<oneshot::Receiver<SocketAddr>>,
}

impl ClientUdpStream {
    pub fn new(server_udp_socket: UdpSocket) -> Self {
        Self {
            server_udp_socket,
            client_udp_addr: None,
        }
    }

    pub fn split<'a>(&'a self) -> (ClientUdpRecvStream<'a>, ClientUdpSendStream<'a>) {
        let (tx, rx) = oneshot::channel();
        (
            ClientUdpRecvStream {
                server_udp_socket: &self.server_udp_socket,
                client_udp_addr: None,
                addr_tx: Some(tx),
            },
            ClientUdpSendStream {
                server_udp_socket: &self.server_udp_socket,
                client_udp_addr: None,
                addr_rx: Some(rx),
            },
        )
    }
}

impl<'a> AsyncRead for ClientUdpRecvStream<'a> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let addr = match ready!(self.server_udp_socket.poll_recv_from(cx, buf)) {
            Ok(addr) => addr,
            Err(e) => {
                return Poll::Ready(Err(e));
            }
        };

        if self.client_udp_addr.is_none() {
            self.client_udp_addr = Some(addr.clone());
            let addr_tx = match self.addr_tx.take() {
                Some(v) => v,
                None => {
                    return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                }
            };
            match addr_tx.send(addr) {
                Ok(_) => {
                    return Poll::Ready(Ok(()));
                }
                Err(_) => {
                    return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                }
            }
        } else {
            if !self.client_udp_addr.map(|v| v == addr).unwrap() {
                return Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<'a> AsyncWrite for ClientUdpSendStream<'a> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.client_udp_addr.is_none() {
            let maybe_addr = match self.addr_rx {
                Some(ref mut rx) => rx.try_recv(),
                None => {
                    return Poll::Ready(Err(std::io::ErrorKind::Other.into()));
                }
            };

            self.client_udp_addr = match maybe_addr {
                Ok(addr) => Some(addr),
                Err(_) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WouldBlock.into()));
                }
            }
        }

        Poll::Ready(ready!(self.server_udp_socket.poll_send_to(
            cx,
            buf,
            self.client_udp_addr.unwrap()
        )))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

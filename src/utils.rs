use anyhow::Result;

use futures::ready;
use std::task::Poll;
use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "Incomplete")]
    Incomplete,
    #[error(display = "Invalid")]
    Invalid,
}

pub fn transmute_u16s_to_u8s(a: &[u16], b: &mut [u8]) {
    if b.len() < a.len() * 2 {
        return;
    }
    for (i, val) in a.iter().enumerate() {
        let x = val.to_be_bytes();
        b[i] = x[0];
        b[i + 1] = x[1];
    }
}

#[derive(Debug)]
pub enum MixAddrType {
    V4(([u8; 4], u16)),
    V6(([u16; 8], u16)),
    Hostname((String, u16)),
    None,
}

impl Default for MixAddrType {
    fn default() -> Self {
        MixAddrType::None
    }
}

impl MixAddrType {
    pub fn is_none(&self) -> bool {
        match self {
            MixAddrType::None => true,
            _ => false,
        }
    }

    pub fn is_ip(&self) -> bool {
        match self {
            MixAddrType::V4(_) => true,
            MixAddrType::V6(_) => true,
            _ => false,
        }
    }

    pub fn host_repr(&self) -> String {
        match self {
            MixAddrType::Hostname((host, port)) => host.to_owned() + &":" + &port.to_string(),
            _ => {
                panic!("only Hostname can use this method");
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        use MixAddrType::*;
        match self {
            Hostname((h, _)) => 2 + h.len() + 2,
            V4(_) => 1 + 4 + 2,
            V6(_) => 1 + 16 + 2,
            MixAddrType::None => panic!("encoded_len() unexpected: MixAddrType::None"),
        }
    }

    pub fn to_socket_addrs(self) -> SocketAddr {
        match self {
            MixAddrType::V4(addr) => addr.into(),
            MixAddrType::V6(addr) => addr.into(),
            _ => {
                panic!("only IP can use this method");
            }
        }
    }

    pub fn from_http_header(is_https: bool, buf: &[u8]) -> Result<Self, ParserError> {
        let end = buf.len();
        let mut port_idx = end;
        let mut port = 0u16;
        for i in (0..buf.len()).rev() {
            if buf[i] == b':' {
                port_idx = i;
                break;
            }
        }

        if port_idx + 1 == end {
            return Err(ParserError::Invalid);
        } else if port_idx == end {
            if is_https {
                port = 80;
            } else {
                return Err(ParserError::Invalid);
            }
        } else {
            for i in (port_idx + 1)..end {
                let di = buf[i];
                if di >= b'0' && di <= b'9' {
                    port = port * 10 + (di - b'0') as u16;
                } else {
                    return Err(ParserError::Invalid);
                }
            }
        }

        let last = buf[buf.len() - 1];
        if last == b']' {
            // IPv6: `[real_IPv6_addr]`
            let str_buf = std::str::from_utf8(buf).map_err(|_| ParserError::Invalid)?;
            let v6_addr_u16 = SocketAddrV6::from_str(str_buf)
                .map_err(|_| ParserError::Invalid)?
                .ip()
                .segments();
            Ok(Self::V6((v6_addr_u16, port)))
        } else if last <= b'z' && last >= b'a' || last <= b'Z' && last >= b'A' {
            // Hostname: ends with alphabetic characters
            Ok(Self::Hostname((
                String::from_utf8(buf.to_vec()).map_err(|_| ParserError::Invalid)?,
                port,
            )))
        } else {
            // IPv4: ends with digit characters
            let str_buf = std::str::from_utf8(buf).map_err(|_| ParserError::Invalid)?;
            Ok(Self::V4((
                SocketAddrV4::from_str(str_buf)
                    .map_err(|_| ParserError::Invalid)?
                    .ip()
                    .octets(),
                port,
            )))
        }
    }

    pub fn write_buf(&self, buf: &mut Vec<u8>) {
        use MixAddrType::*;
        match self {
            Hostname((host, port)) => {
                buf.extend_from_slice(&[0x03, host.len() as u8]);
                buf.extend_from_slice(host.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            V4((ip, port)) => {
                buf.push(0x01);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            V6((ip, port)) => {
                let mut v6_addr_u8 = [0u8; 16];
                transmute_u16s_to_u8s(ip, &mut v6_addr_u8);
                buf.push(0x04);
                buf.extend_from_slice(&v6_addr_u8);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            MixAddrType::None => panic!("as_bytes() unexpected: MixAddrType::None"),
        }
    }

    pub fn init_from(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4((v4.ip().octets(), v4.port())),
            SocketAddr::V6(v6) => Self::V6((v6.ip().segments(), v6.port())),
        }
    }
}

#[macro_export]
macro_rules! expect_buf_len {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Err(ParserError::Incomplete);
        }
    };
    ($buf:expr, $len:expr, $mark:expr) => {
        if $buf.len() < $len {
            debug!("expect_buf_len {}", $mark);
            return Err(ParserError::Incomplete);
        }
    };
}

pub struct ClientUdpStream {
    server_udp_socket: UdpSocket,
    client_udp_addr: Option<SocketAddr>,
}

pub struct ClientUdpRecvStream<'a> {
    server_udp_socket: &'a UdpSocket,
    client_udp_addr: Option<SocketAddr>,
    addr_tx: Option<oneshot::Sender<SocketAddr>>,
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

pub struct ClientUdpSendStream<'a> {
    server_udp_socket: &'a UdpSocket,
    client_udp_addr: Option<SocketAddr>,
    addr_rx: Option<oneshot::Receiver<SocketAddr>>,
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

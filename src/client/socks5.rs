use crate::{
    expect_buf_len,
    proxy::ConnectionRequest,
    utils::{ClientTcpStream, Socks5UdpStream, MixAddrType, ParserError},
};
use anyhow::{Error, Result};
// use futures::future;
// use std::io::IoSlice;
// use std::pin::Pin;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::{io::*, net::UdpSocket};
use tracing::*;

const SOCKS_VERSION_INDEX: usize = 0;
const NUM_SUPPORTED_AUTH_METHOD_INDEX: usize = 1;
const CONNECTION_TYPE_INDEX: usize = 1;
const ADDR_TYPE_INDEX: usize = 3;
const LEN_OF_ADDR_INDEX: usize = 4;
const Phase1ServerReply: [u8; 2] = [0x05, 0x00];
const Phase2ServerReply: [u8; 3] = [0x05, 0x00, 0x00];

pub struct Socks5Request {
    phase: Sock5ParsePhase,
    is_udp: bool,
    addr: MixAddrType,
}

enum Sock5ParsePhase {
    P1ClientHello,
    P2ClientRequest,
}

impl Socks5Request {
    pub fn new() -> Self {
        Self {
            phase: Sock5ParsePhase::P1ClientHello,
            is_udp: false,
            addr: MixAddrType::None,
        }
    }

    pub fn addr(&self) -> &MixAddrType {
        todo!()
        // let start = if self.extracted_request[0] == 0x03 {
        //     2
        // } else {
        //     1
        // };
        // let end = self.extracted_request.len() - 2;
        // unsafe { str::from_utf8_unchecked(&self.extracted_request[start..end]) }
    }

    pub async fn accept(&mut self, mut inbound: TcpStream) -> Result<ConnectionRequest<ClientTcpStream, Socks5UdpStream>> {
        let mut buffer = Vec::with_capacity(200);
        loop {
            let read = inbound.read_buf(&mut buffer).await?;
            if read != 0 {
                match self.parse(&mut buffer) {
                    Ok(_) => {
                        use Sock5ParsePhase::*;
                        match self.phase {
                            P1ClientHello => {
                                inbound.write_all(&Phase1ServerReply).await?;
                                debug!("socks5 Phase 1 parsed");
                                self.phase = P2ClientRequest;
                                unsafe {
                                    // reset buffer
                                    buffer.set_len(0);
                                }
                            }
                            P2ClientRequest => {
                                debug!("socks5 Phase 2 parsed");
                                break;
                            }
                        }
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

        let mut buf = Vec::with_capacity(3 + 1 + 16 + 2);
        buf.extend_from_slice(&Phase2ServerReply);
        if !self.is_udp {
            MixAddrType::init_from(&inbound.local_addr()?).write_buf(&mut buf);
            inbound.write_all(&buf).await?;
            Ok(ConnectionRequest::TCP(ClientTcpStream {
                inner: inbound,
                http_request_extension: None,
            }))
        } else {
            let local_ip = inbound.local_addr()?.ip();
            let server_udp_socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
            MixAddrType::init_from(&server_udp_socket.local_addr()?).write_buf(&mut buf);
            inbound.write_all(&buf).await?;
            let udp_stream = Socks5UdpStream::new(server_udp_socket);
            Ok(ConnectionRequest::UDP((udp_stream, inbound)))
        }
    }

    fn parse(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        use Sock5ParsePhase::*;
        match self.phase {
            P1ClientHello => {
                expect_buf_len!(buf, 2);
                if buf[SOCKS_VERSION_INDEX] != 5 {
                    return Err(ParserError::Invalid); // Only support socks v5
                }
                let num = buf[NUM_SUPPORTED_AUTH_METHOD_INDEX];

                let expected_len = 2 + num as usize;
                expect_buf_len!(buf, expected_len);

                for &method in buf[2..expected_len].iter() {
                    if method == 0 {
                        return Ok(());
                    }
                }
                return Err(ParserError::Invalid);
            }
            P2ClientRequest => {
                expect_buf_len!(buf, 5);
                if buf[SOCKS_VERSION_INDEX] != 5 {
                    return Err(ParserError::Invalid); // Only support socks v5
                }

                match buf[CONNECTION_TYPE_INDEX] {
                    0x01 => {
                        self.is_udp = false;
                    }
                    0x03 => {
                        self.is_udp = true;
                    }
                    _ => {
                        return Err(ParserError::Invalid); // Only support socks v5
                    }
                }

                let field_5_len = match buf[ADDR_TYPE_INDEX] {
                    0x01 => {
                        // IPv4
                        4
                    }
                    0x03 => {
                        // Domain name
                        1 + buf[LEN_OF_ADDR_INDEX] as usize
                    }
                    0x04 => {
                        // IPv6
                        16
                    }
                    _ => {
                        return Err(ParserError::Invalid);
                    }
                };

                expect_buf_len!(buf, 4 + field_5_len + 2);
                let mut extracted_request = Vec::with_capacity(2 + field_5_len + 2);
                extracted_request[0] = if self.is_udp { 0x03 } else { 0x01 };
                extracted_request.extend_from_slice(
                    &buf[ADDR_TYPE_INDEX..ADDR_TYPE_INDEX + 1 + field_5_len + 2],
                );
                self.addr = MixAddrType::EncodedSocks(extracted_request);

                return Ok(());
            }
        }
    }
}

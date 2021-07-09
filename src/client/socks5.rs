use crate::{
    expect_buf_len,
    utils::ConnectionRequest,
    utils::{ClientTcpStream, MixAddrType, ParserError, Socks5UdpStream},
};
use anyhow::{Error, Result};
use std::net::SocketAddr;
use tokio::{io::*, net::UdpSocket};
use tokio::{net::TcpStream, sync::oneshot};
use tracing::*;

const SOCKS_VERSION_INDEX: usize = 0;
const NUM_SUPPORTED_AUTH_METHOD_INDEX: usize = 1;
const CONNECTION_TYPE_INDEX: usize = 1;
const ADDR_TYPE_INDEX: usize = 3;
// const LEN_OF_ADDR_INDEX: usize = 4;
const PHASE1_SERVER_REPLY: [u8; 2] = [0x05, 0x00];
const PHASE2_SERVER_REPLY: [u8; 3] = [0x05, 0x00, 0x00];

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

    pub fn addr(self) -> MixAddrType {
        self.addr
    }

    pub async fn accept(
        &mut self,
        mut inbound: TcpStream,
    ) -> Result<ConnectionRequest<ClientTcpStream, Socks5UdpStream>> {
        let mut buffer = Vec::with_capacity(200);
        loop {
            let read = inbound.read_buf(&mut buffer).await?;
            if read != 0 {
                match self.parse(&mut buffer) {
                    Ok(_) => {
                        use Sock5ParsePhase::*;
                        match self.phase {
                            P1ClientHello => {
                                inbound.write_all(&PHASE1_SERVER_REPLY).await?;
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
                    Err(e @ ParserError::Invalid(_)) => {
                        return Err(Error::new(e));
                    }
                    _ => (),
                }
            } else {
                return Err(Error::new(ParserError::Invalid(
                    "Socks5Request::accept unable to accept before EOF",
                )));
            }
        }

        let mut buf = Vec::with_capacity(3 + 1 + 16 + 2);
        buf.extend_from_slice(&PHASE2_SERVER_REPLY);
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
            let (stream_reset_signal_tx, stream_reset_signal_rx) = oneshot::channel();

            tokio::spawn(async move {
                let mut dummy = [0u8; 3];
                let _ = inbound.read(&mut dummy).await;
                let _ = stream_reset_signal_tx.send(());
            });

            let udp_stream = Socks5UdpStream::new(server_udp_socket, stream_reset_signal_rx);
            Ok(ConnectionRequest::UDP(udp_stream))
        }
    }

    fn parse(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        use Sock5ParsePhase::*;
        match self.phase {
            P1ClientHello => {
                expect_buf_len!(buf, 2);
                if buf[SOCKS_VERSION_INDEX] != 5 {
                    return Err(ParserError::Invalid(
                        "Socks5Request::parse only support socks v5",
                    ));
                }
                let num = buf[NUM_SUPPORTED_AUTH_METHOD_INDEX];

                let expected_len = 2 + num as usize;
                expect_buf_len!(buf, expected_len);

                for &method in buf[2..expected_len].iter() {
                    if method == 0 {
                        return Ok(());
                    }
                }
                return Err(ParserError::Invalid("Socks5Request::parse method invalid"));
            }
            P2ClientRequest => {
                expect_buf_len!(buf, 5);
                if buf[SOCKS_VERSION_INDEX] != 5 {
                    return Err(ParserError::Invalid(
                        "Socks5Request::parse only support socks v5",
                    ));
                }

                match buf[CONNECTION_TYPE_INDEX] {
                    0x01 => {
                        self.is_udp = false;
                    }
                    0x03 => {
                        self.is_udp = true;
                    }
                    _ => {
                        return Err(ParserError::Invalid(
                            "Socks5Request::parse invalid connection type",
                        ));
                    }
                }

                self.addr = MixAddrType::from_encoded_bytes(&buf[ADDR_TYPE_INDEX..])?.0;

                return Ok(());
            }
        }
    }
}

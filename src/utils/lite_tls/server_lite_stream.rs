// use super::{error::EofErr, tls_relay_buffer::TlsRelayBuffer, Direction};
// use crate::utils::{BufferedRecv, ParserError};
// use anyhow::{Error, Result};
// use tokio::{
//     io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
//     net::TcpStream,
//     select,
// };
// use tokio_rustls::server::TlsStream;

// type InboundType = (
//     WriteHalf<TlsStream<TcpStream>>,
//     BufferedRecv<ReadHalf<TlsStream<TcpStream>>>,
// );

// pub struct ServerLiteStream {
//     inbound_buf: TlsRelayBuffer,
//     outbound_buf: TlsRelayBuffer,
//     change_cipher_recieved: usize,
// }

// impl ServerLiteStream {
//     async fn client_hello(&mut self, inbound: &mut InboundType) -> Result<()> {
//         loop {
//             if inbound.1.read(&mut self.inbound_buf).await? == 0 {
//                 return Err(EofErr("EOF on Client Hello"));
//             }
//             match self.inbound_buf.check_client_hello() {
//                 Ok(_) => return Ok(()),
//                 Err(ParserError::Incomplete(_)) => (),
//                 // doesn't look like a tls stream, leave it alone
//                 Err(e @ ParserError::Invalid(_)) => return Err(Error::new(e)),
//             }
//         }
//     }

//     pub async fn handshake(
//         &mut self,
//         inbound: &mut InboundType,
//         outbound: &mut TcpStream,
//     ) -> Result<()> {
//         // Client Hello
//         self.client_hello(inbound).await?;
//         outbound.write(&mut self.inbound_buf).await?;
//         self.inbound_buf.reset();

//         loop {
//             let (res, dir) = select! {
//                 res = inbound.1.inner.read(&mut self.inbound_buf) => {
//                     (res?, Direction::Inbound)
//                 }
//                 res = outbound.read(&mut self.outbound_buf) => {
//                     (res?, Direction::Outbound)
//                 }
//             };

//             if res == 0 {
//                 return Err(EofErr("EOF on Parsing[1]"));
//             }

//             match (
//                 match dir {
//                     Direction::Inbound => &mut self.inbound_buf,
//                     Direction::Outbound => &mut self.outbound_buf,
//                 }
//                 .find_change_cipher_spec(),
//                 dir,
//                 self.change_cipher_recieved,
//             ) {
//                 (_, _, x) if x > 1 => unreachable!(),
//                 (Ok(_), Direction::Inbound, 0) => {
//                     // TLS 1.2 full handshake: client send
//                     // CCS first
//                     self.change_cipher_recieved = 1;
//                 }
//                 (Ok(_), Direction::Inbound, 1) => {
                    
//                 }
//                 (Ok(_), Direction::Outbound, 0) => {
//                     // TLS 1.2 with resumption or TLS 1.3
//                     // server send CCS first
//                     self.change_cipher_recieved = 1;
//                 }
//                 (Ok(_), Direction::Outbound, 1) => {
//                     // TLS 1.2 full handshake
//                     self.change_cipher_recieved = 2;
//                     loop {
//                         match self.outbound_buf.check_type_0x16() {
//                             Ok(_) => {
//                                 // relay till last byte
//                                 if inbound.0.write(&self.outbound_buf).await? == 0 {
//                                     return Err(EofErr("EOF on Parsing[3]"));
//                                 }
//                                 self.outbound_buf.reset();
//                                 // then we are safe to leave TLS channel
//                                 return Ok(());
//                             }
//                             Err(ParserError::Incomplete(_)) => {
//                                 // let's try to read the last encrypted packet
//                                 if outbound.read(&mut self.outbound_buf).await? == 0 {
//                                     return Err(EofErr("EOF on Parsing[4]"));
//                                 }
//                             }
//                             Err(e @ ParserError::Invalid(_)) => {
//                                 return Err(
//                                     Error::new(e).context("tls 1.2 full handshake last step")
//                                 );
//                             }
//                         }
//                     }
//                 }
//                 (Err(ParserError::Incomplete(_)), _, _) => {
//                     // relay pending packets
//                 }
//                 (Err(e @ ParserError::Invalid(_)), dir, seen) => {
//                     return Err(Error::new(e).context(format!("{:?}, {}", dir, seen)));
//                 }
//                 _ => unreachable!(),
//             }
//         }

//         todo!()
//     }
// }

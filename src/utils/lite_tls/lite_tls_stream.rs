use std::ops::DerefMut;

use super::{
    error::eof_err,
    tls_relay_buffer::{Expecting, TlsRelayBuffer, TlsVersion},
};
use crate::utils::ParserError;
use anyhow::{anyhow, Context, Error, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};
use tracing::debug;

#[derive(Debug, Clone, Copy)]
enum LiteTlsEndpointSide {
    #[cfg(feature = "client")]
    ClientSide,
    #[cfg(feature = "server")]
    ServerSide,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Direction {
    Inbound,
    Outbound,
}

pub struct LiteTlsStream {
    inbound_buf: TlsRelayBuffer,
    outbound_buf: TlsRelayBuffer,
    change_cipher_recieved: usize,
    side: LiteTlsEndpointSide,
}

impl LiteTlsStream {
    #[cfg(feature = "server")]
    pub fn new_server_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            change_cipher_recieved: 0,
            side: LiteTlsEndpointSide::ServerSide,
        }
    }

    #[cfg(feature = "client")]
    pub fn new_client_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            change_cipher_recieved: 0,
            side: LiteTlsEndpointSide::ClientSide,
        }
    }

    async fn client_hello<I>(&mut self, inbound: &mut I) -> Result<()>
    where
        I: AsyncReadExt + Unpin,
    {
        loop {
            if inbound.read_buf(self.inbound_buf.deref_mut()).await? == 0 {
                // debug!("EOF on Client Hello");
                return Err(eof_err("EOF on Client Hello"));
            }
            match self.inbound_buf.check_client_hello() {
                Ok(_) => return Ok(()),
                Err(ParserError::Incomplete(e)) => {
                    debug!("client hello incomplete: {}", e);
                }
                // doesn't look like a tls stream, leave it alone
                Err(e @ ParserError::Invalid(_)) => return Err(Error::new(e)),
            }
        }
    }

    /// if Ok(_) is returned, then quit TLS channel, relay the remaining
    /// packets through TCP
    ///
    /// if Err(Invalid) is returned, then relay the remaining packets
    /// through tls
    ///
    /// if Err(other) is returned, the stream is probably non-recoverable
    /// just quit
    pub async fn handshake<I, O>(&mut self, outbound: &mut O, inbound: &mut I) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        self.client_hello(inbound).await?;

        // relay packet
        outbound.write(&self.inbound_buf).await?;
        outbound.flush().await?;
        self.inbound_buf.reset();

        #[cfg(feature = "debug_info")]
        let mut packet_id = 0;

        loop {
            #[cfg(feature = "debug_info")]
            {
                debug!("[0][{}]inbound_buf: {:?}", packet_id, self.inbound_buf);
                debug!("[0][{}]outbound_buf: {:?}", packet_id, self.outbound_buf);
            }
            let (res, dir) = select! {
                res = inbound.read_buf(self.inbound_buf.deref_mut()) => {
                    (res?, Direction::Inbound)
                }
                res = outbound.read_buf(self.outbound_buf.deref_mut()) => {
                    (res?, Direction::Outbound)
                }
            };

            if res == 0 {
                match dir {
                    Direction::Inbound => return Err(eof_err("EOF on Parsing[1][I]")),
                    Direction::Outbound => return Err(eof_err("EOF on Parsing[1][O]")),
                }
            }

            use LiteTlsEndpointSide::*;
            match (
                match dir {
                    Direction::Inbound => &mut self.inbound_buf,
                    Direction::Outbound => &mut self.outbound_buf,
                }
                .find_last_change_cipher_spec(&mut self.change_cipher_recieved, dir),
                self.side,
            ) {
                #[cfg(feature = "client")]
                // TLS 1.2 with resumption or TLS 1.3
                (Ok(TlsVersion::Tls13), ClientSide) => {
                    #[cfg(feature = "debug_info")]
                    debug!("[LC0][{}]buf now: {:?}", packet_id, self.inbound_buf);

                    // relay everything till the end of CCS
                    // there might be some 0x17 packets left
                    if outbound.write(self.inbound_buf.checked_packets()).await? == 0 {
                        return Err(eof_err("EOF on Parsing[2]"));
                    }
                    outbound.flush().await?;
                    self.inbound_buf.pop_checked_packets();

                    #[cfg(feature = "debug_info")]
                    {
                        debug!("[LC0][{}]buf after pop: {:?}", packet_id, self.inbound_buf);
                        debug!("[LC0][{}]outbound buf: {:?}", packet_id, self.outbound_buf);
                    }
                    // wait for server's response
                    // this is not part of the TLS specification,
                    // but we have to do this to correctly
                    // leave TLS channel.
                    if outbound.read_buf(self.outbound_buf.deref_mut()).await? == 0 {
                        return Err(eof_err("EOF on Parsing[7]"));
                    }

                    // check: x must be 6 and the rsp should
                    // be [0x14, 0x03, 0x03, 0, 0x01, 0x01]
                    // (change_cipher_spec)
                    match self.outbound_buf.check_type_0x14() {
                        Ok(_) => {
                            #[cfg(feature = "debug_info")]
                            debug!("[LC0][{}] extra CCS ok, leaving", packet_id);

                            // clear this, since it's not part of
                            // TLS.
                            self.outbound_buf.reset();
                            // Then it's safe for us to leave TLS
                            // outbound_buf: []
                            // inbound_buf: [...]
                            return Ok(());
                        }
                        Err(_) => {
                            // Something's wrong, which I'm not
                            // sure what it is currently.
                            todo!()
                        }
                    }
                }
                // TLS 1.2 with resumption or TLS 1.3
                #[cfg(feature = "server")]
                (Ok(TlsVersion::Tls13), ServerSide) => {
                    #[cfg(feature = "debug_info")]
                    debug!("[LC1][{}]buf now: {:?}", packet_id, self.inbound_buf);

                    // relay everything till the end of CCS
                    if outbound.write(self.inbound_buf.checked_packets()).await? == 0 {
                        return Err(eof_err("EOF on Parsing[2]"));
                    }
                    outbound.flush().await?;
                    self.inbound_buf.pop_checked_packets();

                    #[cfg(feature = "debug_info")]
                    debug!("[LC1][{}]buf after pop: {:?}", packet_id, self.inbound_buf);

                    if self.inbound_buf.len() != 0 {
                        return Err(Error::new(ParserError::Invalid(
                            "buffer not empty after last 0x14".into(),
                        )));
                    }

                    // write a 0x14 response to client
                    // so that both sides can leave TLS channel
                    inbound.write(&[0x14, 0x03, 0x03, 0, 0x01, 0x01]).await?;
                    inbound.flush().await?;

                    #[cfg(feature = "debug_info")]
                    debug!("[LC1][{}]last CCS sent, leaving", packet_id);
                    return Ok(());
                }
                // TLS 1.2 full handshake
                (Ok(TlsVersion::Tls12), _) => {
                    #[cfg(feature = "debug_info")]
                    {
                        debug!("[LC2][{}]out buf now: {:?}", packet_id, self.outbound_buf);
                        debug!("[LC2][{}]in buf now: {:?}", packet_id, self.inbound_buf);
                    }

                    // inbound_buf{client}:
                    // [{0x14}, {0x16}, ...] -> [{0x14}, {0x16}, ...]
                    //    ^       ^                        ^
                    //  checked unchecked                checked
                    //
                    // inbound_buf{server}:
                    // [{0x14}, {0x16}] -> [{0x14}, {0x16}]
                    //    ^       ^                   ^
                    //  checked unchecked           checked
                    //
                    // outbound_buf: []
                    self.inbound_buf
                        .check_tls_packets(Expecting::Num(1), inbound)
                        .await?;

                    // inbound_buf{client}:
                    // [{0x14}, {0x16}, ...] -> [...]
                    // inbound_buf{server}:
                    // [{0x14}, {0x16}] -> []
                    self.inbound_buf.write_checked_packets(outbound).await?;

                    // outbound_buf: [] -> [..., {0x14}, {0x16}]
                    //                             ^       ^
                    //                           checked unchecked
                    self.outbound_buf
                        .check_tls_packets(Expecting::Packet(0x14), outbound)
                        .await?;

                    // outbound_buf: [] -> [..., {0x14}, {0x16}]
                    //                                     ^
                    //                                   checked
                    self.outbound_buf
                        .check_tls_packets(Expecting::Num(1), outbound)
                        .await?;

                    // outbound_buf: [..., {0x14}, {0x16}] -> []
                    self.outbound_buf.write_checked_packets(inbound).await?;

                    // then let's leave TLS channel
                    return Ok(());
                }
                (Err(ParserError::Incomplete(_)), _) => {
                    // relay pending packets
                }
                (Err(e @ ParserError::Invalid(_)), _) => {
                    return Err(Error::new(e))
                        .with_context(|| anyhow!("{:?}, {}", dir, self.change_cipher_recieved));
                }
            }

            #[cfg(feature = "debug_info")]
            {
                debug!("[1][{}]inbound_buf: {:?}", packet_id, self.inbound_buf);
                debug!("[1][{}]outbound_buf: {:?}", packet_id, self.outbound_buf);
            }
            // relay pending bytes
            match dir {
                Direction::Inbound => {
                    if outbound.write(self.inbound_buf.checked_packets()).await? == 0 {
                        return Err(eof_err("EOF on Parsing[5]"));
                    }
                    outbound.flush().await?;
                    self.inbound_buf.pop_checked_packets();
                }
                Direction::Outbound => {
                    if inbound.write(self.outbound_buf.checked_packets()).await? == 0 {
                        return Err(eof_err("EOF on Parsing[6]"));
                    }
                    inbound.flush().await?;
                    self.outbound_buf.pop_checked_packets();
                }
            }

            #[cfg(feature = "debug_info")]
            {
                packet_id += 1;
            }
        }
    }

    pub async fn flush<I, O>(mut self, outbound: &mut O, inbound: &mut I) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if self.inbound_buf.len() > 0 {
            outbound.write(&mut self.inbound_buf).await?;
            outbound.flush().await?;
            self.inbound_buf.reset();
        }
        if self.outbound_buf.len() > 0 {
            inbound.write(&mut self.outbound_buf).await?;
            inbound.flush().await?;
            self.outbound_buf.reset();
        }
        Ok(())
    }
}

use std::ops::DerefMut;

use super::{
    error::eof_err,
    tls_relay_buffer::{LeaveTlsSide, Seen0x17, TlsRelayBuffer},
};
use crate::{protocol::LEAVE_TLS_COMMAND, utils::ParserError};
use anyhow::{anyhow, Context, Error, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};
use tracing::debug;

// #[derive(Debug, Clone, Copy)]
// enum LiteTlsEndpointSide {
//     #[cfg(feature = "client")]
//     ClientSide,
//     #[cfg(feature = "server")]
//     ServerSide,
// }

#[derive(Debug, Clone, Copy)]
pub(super) enum Direction {
    Inbound,
    Outbound,
}

pub struct LiteTlsStream {
    inbound_buf: TlsRelayBuffer,
    outbound_buf: TlsRelayBuffer,
    recieved_0x17: Seen0x17,
}

impl LiteTlsStream {
    pub fn new_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            recieved_0x17: Seen0x17::None,
        }
    }

    async fn relay_pending<I, O>(
        &mut self,
        dir: Direction,
        outbound: &mut O,
        inbound: &mut I,
    ) -> Result<()>
    where
        I: AsyncWriteExt + Unpin,
        O: AsyncWriteExt + Unpin,
    {
        #[cfg(feature = "debug_info")]
        {
            debug!(
                "[1]0x17: {:?}, inbound_buf: {:?}",
                self.recieved_0x17, self.inbound_buf
            );
            debug!("[1]outbound_buf: {:?}", self.outbound_buf);
        }
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
        Ok(())
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
        #[cfg(feature = "debug_info")]
        debug!("lite tls handshake entered");
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
                debug!(
                    "[0][{}]0x17: {:?}, inbound_buf: {:?}",
                    packet_id, self.recieved_0x17, self.inbound_buf
                );
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

            match match dir {
                Direction::Inbound => &mut self.inbound_buf,
                Direction::Outbound => &mut self.outbound_buf,
            }
            .find_first_0x17(&mut self.recieved_0x17, dir)
            {
                Ok(LeaveTlsSide::Active) => {
                    // relay all pending packets
                    self.relay_pending(dir, outbound, inbound).await?;

                    let mut tmp = [0u8; 6];
                    match dir {
                        Direction::Inbound => {
                            if outbound.write(&LEAVE_TLS_COMMAND).await? == 0 {
                                return Err(eof_err("EOF on Parsing[7]"));
                            }
                            outbound.flush().await?;
                            if outbound.read(&mut tmp).await? == 0 {
                                return Err(eof_err("EOF on Parsing[8]"));
                            }
                        }
                        Direction::Outbound => {
                            if inbound.write(&LEAVE_TLS_COMMAND).await? == 0 {
                                return Err(eof_err("EOF on Parsing[9]"));
                            }
                            inbound.flush().await?;

                            if inbound.read(&mut tmp).await? == 0 {
                                return Err(eof_err("EOF on Parsing[10]"));
                            }
                        }
                    }

                    if tmp != LEAVE_TLS_COMMAND {
                        return Err(Error::new(ParserError::Invalid(format!(
                            "expecting LEAVE_TLS_COMMAND, got: {:?} from {:?}",
                            tmp, dir
                        ))));
                    }

                    // Then we leave tls tunnel
                    return Ok(());
                }
                Ok(LeaveTlsSide::Passive) => {
                    // relay all pending packets
                    self.relay_pending(dir, outbound, inbound).await?;
                    match dir {
                        Direction::Inbound => {
                            self.inbound_buf.check_tls_packet()?;
                            self.inbound_buf.pop_checked_packets();

                            if inbound.write(&LEAVE_TLS_COMMAND).await? == 0 {
                                return Err(eof_err("EOF on Parsing[11]"));
                            }
                            inbound.flush().await?;
                        }
                        Direction::Outbound => {
                            self.outbound_buf.check_tls_packet()?;
                            self.outbound_buf.pop_checked_packets();

                            if outbound.write(&LEAVE_TLS_COMMAND).await? == 0 {
                                return Err(eof_err("EOF on Parsing[12]"));
                            }
                            outbound.flush().await?;
                        }
                    }

                    // Then we leave tls tunnel
                    return Ok(());
                }
                Err(ParserError::Incomplete(_)) => {
                    // relay pending packets
                }
                Err(e @ ParserError::Invalid(_)) => {
                    return Err(Error::new(e))
                        .with_context(|| anyhow!("{:?}, {:?}", dir, self.recieved_0x17));
                }
            }

            // relay pending bytes
            self.relay_pending(dir, outbound, inbound).await?;

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

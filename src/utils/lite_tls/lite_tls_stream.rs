use std::ops::DerefMut;

use super::{
    error::eof_err,
    tls_relay_buffer::{LeaveTlsMode, Seen0x17, TlsRelayBuffer},
};
use crate::{
    protocol::LEAVE_TLS_COMMAND,
    utils::{lite_tls::tls_relay_buffer::Expecting, ParserError},
};
use anyhow::{anyhow, Context, Error, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    time::{sleep, Duration},
};
use tracing::{debug, info};

#[derive(Debug, Clone, Copy)]
pub(super) enum LiteTlsEndpointSide {
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
    recieved_0x17: Seen0x17,
    side: LiteTlsEndpointSide,
}

// macro_rules! dir_buf {
//     ($self:ident, $dir:ident) => {
//         match $dir {
//             Direction::Inbound => $self.inbound_buf,
//             Direction::Outbound => $self.outbound_buf,
//         }
//     };
// }

impl LiteTlsStream {
    pub fn new_server_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            recieved_0x17: Seen0x17::None,
            side: LiteTlsEndpointSide::ServerSide,
        }
    }

    pub fn new_client_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            recieved_0x17: Seen0x17::None,
            side: LiteTlsEndpointSide::ClientSide,
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
                if self.inbound_buf.checked_packets().len() == 0 {
                    // don't even try to write, otherwise we may
                    // send an EOF.
                    return Ok(());
                }
                if outbound.write(self.inbound_buf.checked_packets()).await? == 0 {
                    return Err(eof_err("EOF on Parsing[5]"));
                }
                outbound.flush().await?;
                self.inbound_buf.pop_checked_packets();
            }
            Direction::Outbound => {
                if self.outbound_buf.checked_packets().len() == 0 {
                    // don't even try to write, otherwise we may
                    // send an EOF.
                    return Ok(());
                }
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
                    debug!("client hello incomplete: {:?}", e);
                }
                // doesn't look like a tls stream, leave it alone
                Err(e @ ParserError::Invalid(_)) => return Err(Error::new(e)),
            }
        }
    }

    /// if Ok(_) is returned, then quit TLS channel, and relay the remaining
    /// packets through TCP
    ///
    /// if Err(Invalid) is returned, then relay the remaining packets
    /// through tls
    ///
    /// if Err(other) is returned, the stream is probably non-recoverable
    /// just quit
    ///
    /// ```
    ///            [client] -- 0x17 -> [server]
    ///                 ...some traffics...
    ///            [client]            [server] <- 0x17 --
    ///                                   ^ active side *1
    /// <- 0x17 -- [client]            [server]
    ///               ^ passive side *2
    ///            [client] -- 0xff -> [server] *3
    ///            [client]            [server]
    ///               ^quit tls           ^ quit tls
    ///            [client]<-PlainTcp->[server]
    /// ```
    /// *1: active side: the side that first start leaving tls will
    ///     be the active side. It will send one `0x17` packet then
    ///     wait for the `0xff` response. After receiving the response,
    ///     it can cleanly leave the tls tunnel.
    ///
    /// *2: passive side: the other side becomes the passive side. After
    ///     having received the `0x17` packet, it will respond with
    ///     the `0xff`, and leave the tunnel afterwards.
    ///
    /// *3: there might be several `0x17` from the passive side before
    ///     the active side received the `0xff` packet. Make sure they
    ///     are correctly handled.
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
            .find_first_0x17(&mut self.recieved_0x17, dir, self.side)
            {
                Ok(LeaveTlsMode::Active) => {
                    // {dir}_buf: [{0x17}, ...]
                    // {!dir}_buf: []
                    // (
                    //    {dir}_buf is the buffer used by current direction,
                    //    {!dir}_buf is the other buffer
                    // )

                    // {dir}_buf: [] or [{0x17}]
                    // {!dir}_buf: []

                    // {!dir}_buf: [] -> [..., {0xff}] -> [{0xff}] -> []

                    #[cfg(feature = "debug_info")]
                    {
                        debug!("[2][{}]inbound_buf: {:?}", packet_id, self.inbound_buf);
                        debug!("[2][{}]outbound_buf: {:?}", packet_id, self.outbound_buf);
                    }
                    match dir {
                        Direction::Inbound => {
                            self.inbound_buf
                                .relay_until_expected(Expecting::Num(1), inbound, outbound)
                                .await?;
                            #[cfg(feature = "debug_info")]
                            debug!("[3][{}]inbound_buf: {:?}", packet_id, self.inbound_buf);
                            self.outbound_buf
                                .relay_until_expected(Expecting::Type(0xff), outbound, inbound)
                                .await?;
                            #[cfg(feature = "debug_info")]
                            debug!("[3][{}]outbound_buf: {:?}", packet_id, self.outbound_buf);
                            self.outbound_buf.check_tls_packet()?;
                            self.outbound_buf.pop_checked_packets();
                            #[cfg(feature = "debug_info")]
                            debug!("[4][{}]outbound_buf: {:?}", packet_id, self.outbound_buf);
                        }
                        Direction::Outbound => {
                            self.outbound_buf
                                .relay_until_expected(Expecting::Num(1), outbound, inbound)
                                .await?;
                            self.inbound_buf
                                .relay_until_expected(Expecting::Type(0xff), inbound, outbound)
                                .await?;
                            self.inbound_buf.check_tls_packet()?;
                            self.inbound_buf.pop_checked_packets();
                        }
                    }

                    // Then we leave tls tunnel
                    return Ok(());
                }
                Ok(LeaveTlsMode::Passive) => {
                    #[cfg(feature = "debug_info")]
                    {
                        debug!("[2][{}]inbound_buf: {:?}", packet_id, self.inbound_buf);
                        debug!("[2][{}]outbound_buf: {:?}", packet_id, self.outbound_buf);
                    }
                    match dir {
                        Direction::Inbound => {
                            if inbound.write(&LEAVE_TLS_COMMAND).await? == 0 {
                                return Err(eof_err("EOF on Parsing[11]"));
                            }
                            inbound.flush().await?;

                            self.inbound_buf
                                .relay_until_expected(Expecting::Num(1), inbound, outbound)
                                .await?;
                            #[cfg(feature = "debug_info")]
                            debug!("[3][{}]inbound_buf: {:?}", packet_id, self.inbound_buf);
                        }
                        Direction::Outbound => {
                            if outbound.write(&LEAVE_TLS_COMMAND).await? == 0 {
                                return Err(eof_err("EOF on Parsing[12]"));
                            }
                            outbound.flush().await?;
                            #[cfg(feature = "client")]
                            {
                                info!("waiting for 20 millis");
                                sleep(Duration::from_millis(20)).await;
                            }
                            self.outbound_buf
                                .relay_until_expected(Expecting::Num(1), outbound, inbound)
                                .await?;
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

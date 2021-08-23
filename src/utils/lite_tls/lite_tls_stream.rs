use std::{ops::DerefMut, time::Duration};

use super::{
    error::eof_err,
    tls_relay_buffer::{LeaveTlsMode, Seen0x17, TlsRelayBuffer},
};
use crate::{
    protocol::{LEAVE_TLS_COMMAND, LITE_TLS_HANDSHAKE_TIMEOUT},
    utils::ParserError,
};
use anyhow::{anyhow, Context, Error, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    select,
    time::timeout,
};
use tracing::debug;

#[derive(Debug, Clone, Copy)]
pub enum LiteTlsEndpointSide {
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
    pub version: Option<LeaveTlsMode>,
}

macro_rules! first_hand_buf {
    ($self:ident) => {
        match $self.side {
            LiteTlsEndpointSide::ClientSide => &$self.inbound_buf,
            LiteTlsEndpointSide::ServerSide => &$self.outbound_buf,
        }
    };
    (mut $self:ident) => {
        match $self.side {
            LiteTlsEndpointSide::ClientSide => &mut $self.inbound_buf,
            LiteTlsEndpointSide::ServerSide => &mut $self.outbound_buf,
        }
    };
}

macro_rules! second_hand_buf {
    ($self:ident) => {
        match $self.side {
            LiteTlsEndpointSide::ServerSide => &$self.inbound_buf,
            LiteTlsEndpointSide::ClientSide => &$self.outbound_buf,
        }
    };
    (mut $self:ident) => {
        match $self.side {
            LiteTlsEndpointSide::ServerSide => &mut $self.inbound_buf,
            LiteTlsEndpointSide::ClientSide => &mut $self.outbound_buf,
        }
    };
}

impl LiteTlsStream {
    pub fn new_client_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            recieved_0x17: Seen0x17::None,
            side: LiteTlsEndpointSide::ClientSide,
            version: None,
        }
    }

    pub fn new_server_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            recieved_0x17: Seen0x17::None,
            side: LiteTlsEndpointSide::ServerSide,
            version: None,
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
                    debug!("client hello incomplete: {}", e);
                }
                // doesn't look like a tls stream, leave it alone
                Err(e @ ParserError::Invalid(_)) => return Err(Error::new(e)),
            }
        }
    }

    async fn handshake_tls12_active<F, S>(
        &mut self,
        first_hand_io: &mut F,
        second_hand_io: &mut S,
    ) -> Result<()>
    where
        F: AsyncReadExt + AsyncWriteExt + Unpin,
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // relay all packets prior to 0x17, plus a 0xff
        // we send 0xff together with those pending packets
        // to reduce 0.5 round trip
        let mut tmp = Vec::with_capacity(
            first_hand_buf!(self).checked_packets().len() + LEAVE_TLS_COMMAND.len(),
        );
        tmp.extend_from_slice(first_hand_buf!(self).checked_packets());
        first_hand_buf!(mut self).pop_checked_packets();
        tmp.extend_from_slice(&LEAVE_TLS_COMMAND);

        if second_hand_io.write(&tmp).await? == 0 {
            return Err(eof_err("EOF on Parsing[12]"));
        }
        second_hand_io.flush().await?;

        // relay all the packets until 0xff
        second_hand_buf!(mut self)
            .tls12_relay_until_0xff(second_hand_io, first_hand_io)
            .await?;

        // Then we leave tls tunnel
        self.version = Some(LeaveTlsMode::Active);
        return Ok(());
    }

    async fn handshake_tls12_passive<S>(&mut self, second_hand_io: &mut S) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        //? we're not sending the pending packets to user
        //? we send them all together with the 0x17 after
        //? the handshake is over

        // drop the 0xff in outbound_buf
        second_hand_buf!(mut self).drop_0xff()?;

        if second_hand_io.write(&LEAVE_TLS_COMMAND).await? == 0 {
            return Err(eof_err("EOF on Parsing[12]"));
        }
        second_hand_io.flush().await?;

        self.version = Some(LeaveTlsMode::Passive);

        // Then we leave tls tunnel
        return Ok(());
    }

    pub async fn handshake_timeout<I, O>(&mut self, outbound: &mut O, inbound: &mut I) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        timeout(
            Duration::from_secs(LITE_TLS_HANDSHAKE_TIMEOUT),
            self.handshake(outbound, inbound),
        )
        .await
        .map_err(|e| Error::new(e))?
    }

    /// if Ok(_) is returned, then quit TLS channel, relay the remaining
    /// packets through TCP
    ///
    /// if Err(Invalid) is returned, then relay the remaining packets
    /// through tls
    ///
    /// if Err(other) is returned, the stream is probably non-recoverable
    /// just quit
    async fn handshake<I, O>(&mut self, outbound: &mut O, inbound: &mut I) -> Result<()>
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
        let mut packet_id = 0usize;

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
                #[cfg(feature = "debug_info")]
                match dir {
                    Direction::Inbound => debug!("EOF on Parsing[1][I]"),
                    Direction::Outbound => debug!("EOF on Parsing[1][O]"),
                }
                return Ok(());
            }

            use LeaveTlsMode::*;
            use LiteTlsEndpointSide::*;
            match match dir {
                Direction::Inbound => &mut self.inbound_buf,
                Direction::Outbound => &mut self.outbound_buf,
            }
            .find_key_packets(&mut self.recieved_0x17, dir)
            {
                Ok(Active) => {
                    return match self.side {
                        ServerSide => self.handshake_tls12_active(outbound, inbound).await,
                        ClientSide => self.handshake_tls12_active(inbound, outbound).await,
                    };
                }
                Ok(Passive) => {
                    return match self.side {
                        ServerSide => self.handshake_tls12_passive(inbound).await,
                        ClientSide => self.handshake_tls12_passive(outbound).await,
                    };
                }
                Err(ParserError::Incomplete(_)) => (), // relay pending packets
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

    pub async fn flush_tls(
        &mut self,
        first_hand_io: &mut TcpStream,
        second_hand_io: &mut TcpStream,
    ) -> Result<()> {
        #[cfg(feature = "debug_info")]
        {
            debug!("[flush]inbound_buf: {:?}", self.inbound_buf);
            debug!("[flush]outbound_buf: {:?}", self.outbound_buf);
        }

        use LeaveTlsMode::*;
        match self.version {
            Some(Passive) => {
                if second_hand_buf!(self).len() > 0 {
                    if second_hand_io
                        .read_buf(second_hand_buf!(mut self).deref_mut())
                        .await?
                        == 0
                    {
                        return Err(eof_err("EOF on Parsing[7]"));
                    }
                    first_hand_io.write(second_hand_buf!(self)).await?;
                    first_hand_io.flush().await?;
                    second_hand_buf!(mut self).reset();
                }
            }
            Some(Active) => {
                second_hand_io.write(first_hand_buf!(self)).await?;
                second_hand_io.flush().await?;
                first_hand_buf!(mut self).reset();
            }
            None => unreachable!(),
        }

        Ok(())
    }

    pub async fn flush_non_tls<I, O>(mut self, outbound: &mut O, inbound: &mut I) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if self.inbound_buf.len() > 0 {
            outbound.write(&self.inbound_buf).await?;
            outbound.flush().await?;
            self.inbound_buf.reset();
        }
        if self.outbound_buf.len() > 0 {
            inbound.write(&self.outbound_buf).await?;
            inbound.flush().await?;
            self.outbound_buf.reset();
        }
        Ok(())
    }
}

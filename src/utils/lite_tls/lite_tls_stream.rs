use std::{ops::DerefMut, time::Duration};

use super::{
    error::eof_err,
    tls_relay_buffer::{Seen0x17, TlsRelayBuffer, TlsVersion},
};
use crate::{
    protocol::{LEAVE_TLS_COMMAND, LITE_TLS_HANDSHAKE_TIMEOUT},
    utils::ParserError,
};
use anyhow::{anyhow, Context, Error, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
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
}

impl LiteTlsStream {
    pub fn new_client_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            recieved_0x17: Seen0x17::None,
            side: LiteTlsEndpointSide::ClientSide,
        }
    }

    pub fn new_server_endpoint() -> Self {
        Self {
            inbound_buf: TlsRelayBuffer::new(),
            outbound_buf: TlsRelayBuffer::new(),
            recieved_0x17: Seen0x17::None,
            side: LiteTlsEndpointSide::ServerSide,
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

    async fn handshake_tls12_server<I, O>(
        &mut self,
        inbound: &mut I,
        outbound: &mut O,
    ) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // relay all packets prior to 0xff
        if self.inbound_buf.checked_packets().len() > 0 {
            outbound.write(self.inbound_buf.checked_packets()).await?;
            self.inbound_buf.pop_checked_packets();
        }

        // ensure the 0x14 is complete.
        self.inbound_buf.read_single_small_packet(inbound).await?;
        // pop the 0x14.
        self.inbound_buf.pop_checked_packets();

        // relay some 0x16, ..., 0x14, 0x16
        // then the handshake should reach an end
        self.outbound_buf
            .tls12_relay_helper(outbound, inbound)
            .await?;
        // Then we leave tls tunnel
        return Ok(());
    }

    async fn handshake_tls12_client<I, O>(
        &mut self,
        outbound: &mut O,
        inbound: &mut I,
    ) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // relay all packets before 0x17
        let mut tmp =
            Vec::with_capacity(self.inbound_buf.checked_packets().len() + LEAVE_TLS_COMMAND.len());
        tmp.extend_from_slice(self.inbound_buf.checked_packets());
        self.inbound_buf.pop_checked_packets();
        tmp.extend_from_slice(&LEAVE_TLS_COMMAND);
        if outbound.write(&tmp).await? == 0 {
            return Err(eof_err("EOF on Parsing[12]"));
        }
        outbound.flush().await?;

        // relay some 0x16, ..., 0x14, 0x16
        // then the handshake should reach an end
        self.outbound_buf
            .tls12_relay_helper(outbound, inbound)
            .await?;

        // Then we leave tls tunnel
        return Ok(());
    }

    async fn handshake_tls13_client<O>(&mut self, outbound: &mut O) -> Result<()>
    where
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        self.inbound_buf.flush_checked(outbound).await?;
        // wait for server's response
        // this is not part of the TLS specification,
        // but we have to do this to correctly
        // leave TLS channel.
        if outbound.read_buf(self.outbound_buf.deref_mut()).await? == 0 {
            return Err(eof_err("EOF on Parsing[7]"));
        }
        match self.outbound_buf.check_tls_packet() {
            // check: the rsp should
            // be [0x14, 0x03, 0x03, 0, 0x01, 0x01]
            // (change_cipher_spec)
            Ok(ty) => {
                if ty != 0x14 {
                    return Err(Error::new(ParserError::Invalid(
                        "[Active, Tls13]return packet type is not 0x14".into(),
                    )));
                }
                #[cfg(feature = "debug_info")]
                debug!("[LC0] extra CCS ok, leaving");

                // clear this, since it's not part of
                // TLS.
                self.outbound_buf.reset();
                // Then it's safe for us to leave TLS
                // outbound_buf: []
                // inbound_buf: [...]
                return Ok(());
            }
            Err(e) => {
                // Something's wrong, which I'm not
                // sure what it is currently.
                return Err(Error::new(e))
                    .with_context(|| anyhow!("[Active, Tls13]failed at last step"));
            }
        }
    }

    async fn handshake_tls13_server<I, O>(
        &mut self,
        inbound: &mut I,
        outbound: &mut O,
    ) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // write a 0x14 response to client
        // so that both sides can leave TLS channel
        // we do this first to reduce latency
        inbound.write(&[0x14, 0x03, 0x03, 0, 0x01, 0x01]).await?;
        inbound.flush().await?;

        self.inbound_buf.flush_checked(outbound).await?;
        if self.inbound_buf.len() != 0 {
            return Err(Error::new(ParserError::Invalid(
                "buffer not empty after last 0x14".into(),
            )));
        }

        #[cfg(feature = "debug_info")]
        debug!("[LC1]last CCS sent, leaving");
        return Ok(());
    }

    async fn handshake_tls13<I, O>(&mut self, outbound: &mut O, inbound: &mut I) -> Result<()>
    where
        I: AsyncReadExt + AsyncWriteExt + Unpin,
        O: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        #[cfg(feature = "debug_info")]
        debug!("[LC0]buf now: {:?}", self.inbound_buf);

        // ensure the 0x14 is complete.
        self.inbound_buf.read_single_small_packet(inbound).await?;
        #[cfg(feature = "debug_info")]
        {
            debug!("[LC0]buf after pop: {:?}", self.inbound_buf);
            debug!("[LC0]outbound buf: {:?}", self.outbound_buf);
        }

        use LiteTlsEndpointSide::*;
        return match self.side {
            ClientSide => self.handshake_tls13_client(outbound).await,
            ServerSide => self.handshake_tls13_server(inbound, outbound).await,
        };
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
                match dir {
                    Direction::Inbound => return Err(eof_err("EOF on Parsing[1][I]")),
                    Direction::Outbound => return Err(eof_err("EOF on Parsing[1][O]")),
                }
            }

            use LiteTlsEndpointSide::*;
            use TlsVersion::*;
            match match dir {
                Direction::Inbound => &mut self.inbound_buf,
                Direction::Outbound => &mut self.outbound_buf,
            }
            .find_key_packets(&mut self.recieved_0x17, dir)
            {
                Ok(Tls12) => {
                    return match self.side {
                        ServerSide => self.handshake_tls12_server(inbound, outbound).await,
                        ClientSide => self.handshake_tls12_client(outbound, inbound).await,
                    };
                }
                Ok(Tls13) => {
                    return self.handshake_tls13(outbound, inbound).await;
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

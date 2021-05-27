use crate::{
    expect_buf_len,
    utils::{MixAddrType, ParserError},
};
use anyhow::Result;
use quinn::*;
use tokio::io::AsyncReadExt;
use tracing::*;

pub mod trojan;

pub const HASH_LEN: usize = 56;

#[derive(Default, Debug)]
pub struct Target<'a> {
    host: MixAddrType,
    cursor: usize,
    password_hash: &'a [u8],
    buf: Vec<u8>,
}

impl<'a> Target<'a> {
    pub fn new(password_hash: &[u8]) -> Target {
        Target {
            password_hash,
            ..Default::default()
        }
    }

    fn verify(&mut self) -> Result<(), ParserError> {
        if self.buf.len() < HASH_LEN {
            return Err(ParserError::Incomplete);
        }

        if &self.buf[..HASH_LEN] == self.password_hash {
            self.cursor = HASH_LEN + 2;
            Ok(())
        } else {
            Err(ParserError::Invalid)
        }
    }

    fn set_host_and_port(&mut self) -> Result<(), ParserError> {
        expect_buf_len!(self.buf, HASH_LEN + 5); // HASH + \r\n + cmd(2 bytes) + host_len(1 byte, only valid when address is hostname)
        self.host = MixAddrType::from_encoded(&mut (&mut self.cursor, &self.buf))?;
        Ok(())
    }

    pub async fn accept(&mut self, in_read: &mut RecvStream) -> Result<(), ParserError> {
        loop {
            let read = in_read
                .read_buf(&mut self.buf)
                .await
                .map_err(|_| ParserError::Invalid)?;
            if read != 0 {
                match self.parse() {
                    Err(ParserError::Invalid) => {
                        debug!("invalid");
                        return Err(ParserError::Invalid);
                    }
                    Err(ParserError::Incomplete) => {
                        debug!("Incomplete");
                        continue;
                    }
                    Ok(()) => {
                        debug!("Ok");
                        break;
                    }
                }
            } else {
                return Err(ParserError::Invalid);
            }
        }
        Ok(())
    }

    pub fn parse(&mut self) -> Result<(), ParserError> {
        debug!(
            "parse begin, cursor {}, buffer({}): {:?}",
            self.cursor,
            self.buf.len(),
            &self.buf[self.cursor..]
        );
        if self.cursor == 0 {
            self.verify()?;
            debug!("verified");
        }

        if self.host.is_none() {
            self.set_host_and_port()?;
        }

        debug!("target: {:?}", self);

        expect_buf_len!(self.buf, self.cursor + 2);
        if &self.buf[self.cursor..self.cursor + 2] == b"\r\n" {
            self.cursor += 2;
            Ok(())
        } else {
            Err(ParserError::Invalid)
        }
    }
}

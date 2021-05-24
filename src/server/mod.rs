use crate::{
    expect_buf_len,
    utils::{MixAddrType, ParserError},
};
use anyhow::Result;
use tracing::*;

pub mod trojan;

pub const HASH_LEN: usize = 56;

#[derive(Default, Debug)]
pub struct Target<'a> {
    host: MixAddrType,
    cursor: usize,
    password_hash: &'a [u8],
}

impl<'a> Target<'a> {
    pub fn new(password_hash: &[u8]) -> Target {
        Target {
            password_hash,
            ..Default::default()
        }
    }

    fn verify(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        if buf.len() < HASH_LEN {
            return Err(ParserError::Incomplete);
        }

        if &buf[..HASH_LEN] == self.password_hash {
            self.cursor = HASH_LEN + 2;
            Ok(())
        } else {
            Err(ParserError::Invalid)
        }
    }

    fn set_host_and_port(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        expect_buf_len!(buf, HASH_LEN + 5); // HASH + \r\n + cmd(2 bytes) + host_len(1 byte, only valid when address is hostname)
        self.host = MixAddrType::from_encoded(&mut (&mut self.cursor, buf))?;
        Ok(())
    }

    pub fn parse(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        debug!(
            "parse begin, cursor {}, buffer({}): {:?}",
            self.cursor,
            buf.len(),
            &buf[self.cursor..]
        );
        if self.cursor == 0 {
            self.verify(buf)?;
            debug!("verified");
        }

        if self.host.is_none() {
            self.set_host_and_port(buf)?;
        }

        debug!("target: {:?}", self);

        expect_buf_len!(buf, self.cursor + 2);
        if &buf[self.cursor..self.cursor + 2] == b"\r\n" {
            self.cursor += 2;
            Ok(())
        } else {
            Err(ParserError::Invalid)
        }
    }
}

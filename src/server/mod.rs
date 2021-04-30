use anyhow::Result;
use crate::utils::ParserError;

pub mod trojan;

pub const HASH_LEN: usize = 56;

#[derive(Default)]
struct Target<'a> {
    host: String,
    port: u16,
    cursor: usize,
    password_hash: &'a [u8],
}

impl<'a> Target<'a> {
    fn new(password_hash: &[u8]) -> Target {
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
            self.cursor = HASH_LEN + 4;
        }
        Ok(())
    }

    fn set_host_and_port(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        if buf.len() <= self.cursor {
            return Err(ParserError::Incomplete);
        }
        
        Ok(())
    }

    fn accept(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        if self.cursor == 0 {
            self.verify(buf)?;
        }

        self.set_host_and_port(buf)?;


        Ok(())
    }
}

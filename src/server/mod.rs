use crate::utils::MixAddrType;
use crate::utils::ParserError;
use anyhow::Result;
use tracing::*;

pub mod trojan;

pub const HASH_LEN: usize = 56;

#[derive(Default, Debug)]
pub struct Target<'a> {
    host: MixAddrType,
    port: u16,
    cursor: usize,
    host_len: usize,
    password_hash: &'a [u8],
}

macro_rules! expect_buf_len {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Err(ParserError::Incomplete);
        }
    };
    ($buf:expr, $len:expr, $mark:expr) => {
        if $buf.len() < $len {
            trace!("expect_buf_len {}", $mark);
            return Err(ParserError::Incomplete);
        }
    };
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
        expect_buf_len!(buf, HASH_LEN + 5, 1); // HASH + \r\n + cmd(2 bytes) + host_len(1 byte, only valid when address is hostname)

        match buf[HASH_LEN + 3] {
            1 => {
                expect_buf_len!(buf, HASH_LEN + 4 + 4 + 2, 2); // HASH + \r\n + cmd + ipv4 + port
                let ip = [
                    buf[HASH_LEN + 4],
                    buf[HASH_LEN + 5],
                    buf[HASH_LEN + 6],
                    buf[HASH_LEN + 7],
                ];
                self.host = MixAddrType::V4(ip);
                self.port = u16::from_be_bytes([buf[HASH_LEN + 8], buf[HASH_LEN + 9]]);
                self.cursor = HASH_LEN + 10;
            }
            3 => {
                self.host_len = buf[HASH_LEN + 4] as usize;
                // HASH + \r\n + cmd + host_len + host(host_len bytes) + port
                expect_buf_len!(buf, HASH_LEN + 5 + self.host_len + 2, 3);
                self.host = MixAddrType::Hostname(
                    String::from_utf8(buf[HASH_LEN + 5..HASH_LEN + 5 + self.host_len].to_vec())
                        .map_err(|_| ParserError::Invalid)?,
                );
                self.cursor = HASH_LEN + 5 + self.host_len;
                self.port = u16::from_be_bytes([buf[self.cursor], buf[self.cursor + 1]]);
                self.cursor += 2;
            }
            4 => {
                // HASH + \r\n + cmd + ipv6u8(16 bytes) + port
                expect_buf_len!(buf, HASH_LEN + 4 + 16 + 2, 4);
                let v6u8 = &buf[HASH_LEN + 4..HASH_LEN + 4 + 16];
                let mut v6u16 = [0u16; 8];
                for i in 0..8 {
                    v6u16[i] = u16::from_be_bytes([v6u8[i], v6u8[i + 1]]);
                }
                self.host = MixAddrType::V6u16(v6u16);
                self.port = u16::from_be_bytes([buf[HASH_LEN + 20], buf[HASH_LEN + 21]]);
                self.cursor = HASH_LEN + 22;
            }
            _ => {
                return Err(ParserError::Invalid);
            }
        }

        Ok(())
    }

    pub fn parse(&mut self, buf: &Vec<u8>) -> Result<(), ParserError> {
        trace!(
            "parse begin, cursor {}, buffer({}): {:?}",
            self.cursor,
            buf.len(),
            &buf[self.cursor..]
        );
        if self.cursor == 0 {
            self.verify(buf)?;
            trace!("verified");
        }

        if self.host.is_none() {
            self.set_host_and_port(buf)?;
        }

        trace!("target: {:?}", self);

        expect_buf_len!(buf, self.cursor + 2);
        if &buf[self.cursor..self.cursor + 2] == b"\r\n" {
            self.cursor += 2;
            Ok(())
        } else {
            Err(ParserError::Invalid)
        }
    }
}

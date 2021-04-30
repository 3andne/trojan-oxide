use anyhow::Result;
use std::{net::{SocketAddr, SocketAddrV6, ToSocketAddrs}, str::FromStr};

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "Incomplete")]
    Incomplete,
    #[error(display = "Invalid")]
    Invalid,
}

pub enum MixAddrType {
    v4([u8; 4]),
    v6([u16; 8]),
    hostname(String),
}

impl MixAddrType {
    fn from(buf: &[u8]) -> Result<Self, ParserError> {
        for &i in buf {
            if i == b':' {
                let str_buf = std::str::from_utf8(buf).map_err(|_| ParserError::Invalid)?;
                let x = SocketAddrV6::from_str(str_buf).map_err(|_| ParserError::Invalid)?;
                return Ok(Self::v6(x.ip().segments()));
            }
        }
        todo!()
    }
}

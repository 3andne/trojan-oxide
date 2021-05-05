use anyhow::Result;
use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};

#[derive(Debug, err_derive::Error)]
pub enum ParserError {
    #[error(display = "Incomplete")]
    Incomplete,
    #[error(display = "Invalid")]
    Invalid,
}

pub fn transmute_u16s_to_u8s(a: &[u16], b: &mut [u8]) {
    if b.len() < a.len() * 2 {
        return;
    }
    for (i, val) in a.iter().enumerate() {
        let x = val.to_be_bytes();
        b[i] = x[0];
        b[i + 1] = x[1];
    }
}

#[derive(Debug)]
pub enum MixAddrType {
    V4([u8; 4]),
    V6u8([u8; 16]),
    V6u16([u16; 8]),
    Hostname(String),
    None,
}

impl Default for MixAddrType {
    fn default() -> Self {
        MixAddrType::None
    }
}

impl MixAddrType {
    pub fn is_none(&self) -> bool {
        match self {
            MixAddrType::None => true,
            _ => false,
        }
    }

    pub fn is_hostname(&self) -> bool {
        match self {
            MixAddrType::Hostname(_) => true,
            _ => false,
        }
    }

    pub fn is_ip(&self) -> bool {
        match self {
            MixAddrType::V4(_) => true,
            MixAddrType::V6u16(_) => true,
            _ => false,
        }
    }

    pub fn unwrap_hostname(self) -> String {
        match self {
            MixAddrType::Hostname(host) => host,
            _ => {
                panic!("only Hostname can use this method");
            }
        }
    }

    pub fn len(&self) -> u8 {
        match self {
            MixAddrType::Hostname(h) => h.len() as u8,
            _ => 0,
        }
    }

    pub fn socks_type(&self) -> u8 {
        match self {
            MixAddrType::V4(_) => 1,
            MixAddrType::Hostname(_) => 3,
            MixAddrType::V6u8(_) => 4,
            MixAddrType::None => panic!("socks_type() unexpected: MixAddrType::None"),
            MixAddrType::V6u16(_) => panic!("socks_type() unexpected: MixAddrType::V6u16"),
        }
    }

    pub fn to_socket_addrs(self, port: u16) -> SocketAddr {
        match self {
            MixAddrType::V4(ip) => (ip, port).into(),
            MixAddrType::V6u16(ip) => (ip, port).into(),
            _ => {
                panic!("only IP can use this method");
            }
        }
    }

    pub fn from_http_header(buf: &[u8]) -> Result<Self, ParserError> {
        let last = buf[buf.len() - 1];
        if last == b']' {
            // IPv6: `[real_IPv6_addr]`
            let str_buf = std::str::from_utf8(buf).map_err(|_| ParserError::Invalid)?;
            let v6_addr_u16 = SocketAddrV6::from_str(str_buf)
                .map_err(|_| ParserError::Invalid)?
                .ip()
                .segments();
            let mut v6_addr_u8 = [0u8; 16];
            transmute_u16s_to_u8s(&v6_addr_u16, &mut v6_addr_u8);
            Ok(Self::V6u8(v6_addr_u8))
        } else if last <= b'z' && last >= b'a' || last <= b'Z' && last >= b'A' {
            // Hostname: ends with alphabetic characters
            Ok(Self::Hostname(
                String::from_utf8(buf.to_vec()).map_err(|_| ParserError::Invalid)?,
            ))
        } else {
            // IPv4: ends with digit characters
            let str_buf = std::str::from_utf8(buf).map_err(|_| ParserError::Invalid)?;
            Ok(Self::V4(
                SocketAddrV4::from_str(str_buf)
                    .map_err(|_| ParserError::Invalid)?
                    .ip()
                    .octets(),
            ))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        use MixAddrType::*;
        match self {
            Hostname(h) => h.as_bytes(),
            V4(ip) => ip,
            V6u8(ip) => ip,
            MixAddrType::V6u16(_) => panic!("as_bytes() unexpected: MixAddrType::V6u16"),
            MixAddrType::None => panic!("as_bytes() unexpected: MixAddrType::None"),
        }
    }
}

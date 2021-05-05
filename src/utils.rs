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
    V4(([u8; 4], u16)),
    V6(([u16; 8], u16)),
    Hostname((String, u16)),
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

    pub fn is_ip(&self) -> bool {
        match self {
            MixAddrType::V4(_) => true,
            MixAddrType::V6(_) => true,
            _ => false,
        }
    }

    pub fn host_repr(&self) -> String {
        match self {
            MixAddrType::Hostname((host, port)) => host.to_owned() + &":" + &port.to_string(),
            _ => {
                panic!("only Hostname can use this method");
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        use MixAddrType::*;
        match self {
            Hostname((h, _)) => 2 + h.len() + 2,
            V4(_) => 1 + 4 + 2,
            V6(_) => 1 + 16 + 2,
            MixAddrType::None => panic!("encoded_len() unexpected: MixAddrType::None"),
        }
    }

    pub fn to_socket_addrs(self) -> SocketAddr {
        match self {
            MixAddrType::V4(addr) => addr.into(),
            MixAddrType::V6(addr) => addr.into(),
            _ => {
                panic!("only IP can use this method");
            }
        }
    }

    pub fn from_http_header(is_https: bool, buf: &[u8]) -> Result<Self, ParserError> {
        let end = buf.len();
        let mut port_idx = end;
        let mut port = 0u16;
        for i in (0..buf.len()).rev() {
            if buf[i] == b':' {
                port_idx = i;
                break;
            }
        }

        if port_idx + 1 == end {
            return Err(ParserError::Invalid);
        } else if port_idx == end {
            if is_https {
                port = 80;
            } else {
                return Err(ParserError::Invalid);
            }
        } else {
            for i in (port_idx + 1)..end {
                let di = buf[i];
                if di >= b'0' && di <= b'9' {
                    port = port * 10 + (di - b'0') as u16;
                } else {
                    return Err(ParserError::Invalid);
                }
            }
        }

        let last = buf[buf.len() - 1];
        if last == b']' {
            // IPv6: `[real_IPv6_addr]`
            let str_buf = std::str::from_utf8(buf).map_err(|_| ParserError::Invalid)?;
            let v6_addr_u16 = SocketAddrV6::from_str(str_buf)
                .map_err(|_| ParserError::Invalid)?
                .ip()
                .segments();
            Ok(Self::V6((v6_addr_u16, port)))
        } else if last <= b'z' && last >= b'a' || last <= b'Z' && last >= b'A' {
            // Hostname: ends with alphabetic characters
            Ok(Self::Hostname((
                String::from_utf8(buf.to_vec()).map_err(|_| ParserError::Invalid)?,
                port,
            )))
        } else {
            // IPv4: ends with digit characters
            let str_buf = std::str::from_utf8(buf).map_err(|_| ParserError::Invalid)?;
            Ok(Self::V4((
                SocketAddrV4::from_str(str_buf)
                    .map_err(|_| ParserError::Invalid)?
                    .ip()
                    .octets(),
                port,
            )))
        }
    }

    pub fn write_buf(&self, buf: &mut Vec<u8>) {
        use MixAddrType::*;
        match self {
            Hostname((host, port)) => {
                buf.extend_from_slice(&[0x03, host.len() as u8]);
                buf.extend_from_slice(host.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            V4((ip, port)) => {
                buf.push(0x01);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            V6((ip, port)) => {
                let mut v6_addr_u8 = [0u8; 16];
                transmute_u16s_to_u8s(ip, &mut v6_addr_u8);
                buf.push(0x04);
                buf.extend_from_slice(&v6_addr_u8);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            MixAddrType::None => panic!("as_bytes() unexpected: MixAddrType::None"),
        }
    }

    pub fn init_from(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4((v4.ip().octets(), v4.port())),
            SocketAddr::V6(v6) => Self::V6((v6.ip().segments(), v6.port())),
        }
    }
}

#[macro_export]
macro_rules! expect_buf_len {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Err(ParserError::Incomplete);
        }
    };
    ($buf:expr, $len:expr, $mark:expr) => {
        if $buf.len() < $len {
            debug!("expect_buf_len {}", $mark);
            return Err(ParserError::Incomplete);
        }
    };
}

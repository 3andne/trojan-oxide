use anyhow::Result;

// use tracing::*;
use crate::{
    expect_buf_len,
    utils::{transmute_u16s_to_u8s, CursoredBuffer, ExtendableFromSlice, ParserError},
};
use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};
#[derive(Debug, Clone)]
pub enum MixAddrType {
    V4(([u8; 4], u16)),
    V6(([u16; 8], u16)),
    Hostname((String, u16)),
    EncodedSocks(Vec<u8>),
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
            EncodedSocks(_) => unimplemented!(),
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

    pub fn write_buf<T: ExtendableFromSlice>(&self, buf: &mut T) {
        use MixAddrType::*;
        match self {
            Hostname((host, port)) => {
                buf.extend_from_slice(&[0x03, host.len() as u8]);
                buf.extend_from_slice(host.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            V4((ip, port)) => {
                buf.extend_from_slice(&[0x01]);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            V6((ip, port)) => {
                let mut v6_addr_u8 = [0u8; 16];
                transmute_u16s_to_u8s(ip, &mut v6_addr_u8);
                buf.extend_from_slice(&[0x04]);
                buf.extend_from_slice(&v6_addr_u8);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            MixAddrType::None => panic!("as_bytes() unexpected: MixAddrType::None"),
            EncodedSocks(en) => {
                buf.extend_from_slice(en);
            }
        }
    }

    ///```not_rust
    ///     The SOCKS request is formed as follows:
    ///
    ///     +----+-----+-------+------+----------+----------+
    ///     |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///     +----+-----+-------+------+----------+----------+
    ///     | 1  |  1  | X'00' |  1   | Variable |    2     |
    ///     +----+-----+-------+------+----------+----------+

    ///  Where:

    ///       o  VER    protocol version: X'05'
    ///       o  CMD
    ///          o  CONNECT X'01'
    ///          o  BIND X'02'
    ///          o  UDP ASSOCIATE X'03'
    ///       o  RSV    RESERVED
    ///       o  ATYP   address type of following address
    ///          o  IP V4 address: X'01'
    ///          o  DOMAINNAME: X'03'
    ///          o  IP V6 address: X'04'
    ///       o  DST.ADDR       desired destination address
    ///       o  DST.PORT desired destination port in network octet
    ///          order
    ///```
    fn from_encoded_bytes(buf: &[u8]) -> Result<(MixAddrType, usize), ParserError> {
        expect_buf_len!(buf, 2);
        match buf[0] {
            // Field ATYP
            0x01 => {
                // IPv4
                expect_buf_len!(buf, 1 + 4 + 2); // cmd + ipv4 + port
                let ip = [buf[1], buf[2], buf[3], buf[4]];
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((MixAddrType::V4((ip, port)), 7))
            }
            0x03 => {
                // Domain Name
                let host_len = buf[1] as usize;
                expect_buf_len!(buf, 1 + 1 + host_len + 2); // cmd + host_len + host(host_len bytes) + port
                let host = String::from_utf8(buf[2..2 + host_len].to_vec())
                    .map_err(|_| ParserError::Invalid)?;
                let port = u16::from_be_bytes([buf[2 + host_len], buf[2 + host_len + 1]]);
                Ok((MixAddrType::Hostname((host, port)), 1 + 1 + host_len + 2))
            }
            0x04 => {
                // IPv6
                expect_buf_len!(buf, 1 + 16 + 2); // cmd + ipv6u8(16 bytes) + port
                let v6u8 = &buf[1..1 + 16];
                let mut v6u16 = [0u16; 8];
                for i in 0..8 {
                    v6u16[i] = u16::from_be_bytes([v6u8[i], v6u8[i + 1]]);
                }
                let port = u16::from_be_bytes([buf[1 + 16], buf[1 + 16 + 1]]);
                Ok((MixAddrType::V6((v6u16, port)), 1 + 16 + 2))
            }
            _ => {
                return Err(ParserError::Invalid);
            }
        }
    }

    pub fn from_encoded<T: CursoredBuffer>(
        cursored_buf: &mut T,
    ) -> Result<MixAddrType, ParserError> {
        let buf = cursored_buf.chunk();
        Self::from_encoded_bytes(buf).map(|(addr, len)| {
            cursored_buf.advance(len);
            addr
        })
    }

    pub fn init_from(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4((v4.ip().octets(), v4.port())),
            SocketAddr::V6(v6) => Self::V6((v6.ip().segments(), v6.port())),
        }
    }

    pub fn new_null() -> Self {
        Self::V4(([0, 0, 0, 0], 0))
    }
}

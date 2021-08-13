#![allow(dead_code)]
use std::time::Duration;

pub const HASH_LEN: usize = 56;
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
pub const ECHO_PHRASE: &str = "echo";
pub const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
pub const MAX_CONCURRENT_BIDI_STREAMS: usize = 30;

pub const TCP_REQUEST_CMD: u8 = 0x01;
pub const UDP_REQUEST_CMD: u8 = 0x03;
pub const ECHO_REQUEST_CMD: u8 = 0xff;
pub const LITE_TLS_REQUEST_CMD: u8 = 0x11;

pub const TCP_MAX_IDLE_TIMEOUT: u16 = 10 * 60;
pub const SERVER_OUTBOUND_CONNECT_TIMEOUT: u64 = 10;
pub const LITE_TLS_HANDSHAKE_TIMEOUT: u64 = 60;

pub const LEAVE_TLS_COMMAND: [u8; 6] = [0xff, 0x03, 0x03, 0, 0x01, 0x01];

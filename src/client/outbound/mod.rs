mod connect;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "tcp_tls")]
pub mod tcp_tls;
pub mod trojan_auth;

pub(super) use connect::forward;

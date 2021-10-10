#[derive(Clone)]
#[cfg_attr(feature = "debug_info", derive(Debug))]
pub enum ConnectionMode {
    #[cfg(feature = "tcp_tls")]
    TcpTLS,
    #[cfg(feature = "quic")]
    Quic,
    #[cfg(feature = "lite_tls")]
    LiteTLS,
}

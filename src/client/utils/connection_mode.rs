#[derive(Debug, Clone)]
pub enum ConnectionMode {
    #[cfg(feature = "tcp_tls")]
    TcpTLS,
    #[cfg(feature = "quic")]
    Quic,
    #[cfg(feature = "lite_tls")]
    LiteTLS,
}

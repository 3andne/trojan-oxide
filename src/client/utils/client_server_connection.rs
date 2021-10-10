use tokio::net::TcpStream;

#[cfg(feature = "quic")]
use quinn::*;
#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use tokio_rustls::client::TlsStream;

pub enum ClientServerConnection {
    #[cfg(feature = "quic")]
    Quic((SendStream, RecvStream)),
    #[cfg(feature = "tcp_tls")]
    TcpTLS(TlsStream<TcpStream>),
    #[cfg(feature = "lite_tls")]
    LiteTLS(TlsStream<TcpStream>),
}

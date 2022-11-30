#[cfg(feature = "client")]
use crate::client::ConnectionMode;
use crate::protocol::HASH_LEN;
use sha2::{Digest, Sha224};
use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::sync::broadcast;

fn parse_log_level(l: &str) -> tracing::Level {
    match &l.to_lowercase()[..] {
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

#[cfg(feature = "client")]
fn parse_connection_mode(l: &str) -> ConnectionMode {
    use ConnectionMode::*;
    #[allow(unreachable_patterns)]
    match &l.to_lowercase()[..] {
        #[cfg(feature = "tcp_tls")]
        "tcp-tls" => TcpTLS,
        #[cfg(feature = "tcp_tls")]
        "t" => TcpTLS,
        #[cfg(feature = "tcp_tls")]
        "tcp" => TcpTLS,
        #[cfg(feature = "tcp_tls")]
        "tcp_tls" => TcpTLS,
        #[cfg(feature = "quic")]
        "quic" => Quic,
        #[cfg(feature = "quic")]
        "q" => Quic,
        #[cfg(feature = "lite_tls")]
        "l" => LiteTLS,
        #[cfg(feature = "tcp_tls")]
        _ => TcpTLS,
        #[cfg(feature = "lite_tls")]
        #[allow(unreachable_patterns)]
        _ => LiteTLS,
        #[cfg(feature = "quic")]
        #[allow(unreachable_patterns)]
        _ => Quic,
    }
}

#[cfg(feature = "client")]
fn into_local_addr(l: &str) -> SocketAddr {
    ("127.0.0.1:".to_owned() + l).parse::<SocketAddr>().unwrap()
}

fn into_u16(l: &str) -> u16 {
    let mut res = 0;
    for i in l.bytes() {
        if i <= b'9' && i >= b'0' {
            res = res * 10 + (i - b'0') as u16;
        } else {
            panic!("invalid port value")
        }
    }
    res
}

fn password_to_hash(s: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(s);
    let h = hasher.finalize();
    let mut s = String::with_capacity(HASH_LEN);
    for i in h {
        write!(&mut s, "{:02x}", i).unwrap();
    }
    s
}

#[derive(StructOpt, Clone)]
#[cfg_attr(feature = "debug_info", derive(Debug))]
#[structopt(name = "basic")]
pub struct Opt {
    /// client http proxy port
    #[cfg(feature = "client")]
    #[structopt(short = "h", long = "http_port", default_value = "8888", parse(from_str = into_local_addr))]
    pub local_http_addr: SocketAddr,

    /// client socks5 proxy port
    #[cfg(feature = "client")]
    #[structopt(short = "5", long = "socks5_port", default_value = "8889", parse(from_str = into_local_addr))]
    pub local_socks5_addr: SocketAddr,

    /// Log level (from least to most verbose): 
    /// 
    /// error < warn < info < debug < trace
    #[structopt(short = "l", long, default_value = "info", parse(from_str = parse_log_level))]
    pub log_level: tracing::Level,

    #[structopt(parse(from_os_str), long = "ca")]
    pub ca: Option<PathBuf>,

    /// Server Name Indication (sni), or Hostname.
    #[structopt(short = "u", long, default_value = "localhost")]
    pub server_hostname: String,

    /// server proxy port
    #[structopt(short = "x", long, default_value = "443", parse(from_str = into_u16))]
    pub server_port: u16,

    /// server ip address
    #[structopt(short = "d", long, default_value = "")]
    pub server_ip: String,

    /// whether to start as server
    #[structopt(short, long)]
    pub server: bool,

    /// TLS private key in PEM format
    #[cfg(feature = "server")]
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    pub key: Option<PathBuf>,

    /// TLS certificate in PEM format
    #[cfg(feature = "server")]
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    pub cert: Option<PathBuf>,

    /// the password to authenticate connections
    #[structopt(short = "w", long, parse(from_str = password_to_hash))]
    pub password: String,

    /// port to re-direct unauthenticated connections
    #[cfg(feature = "server")]
    #[structopt(short = "f", long, default_value = "0", parse(from_str = into_u16))]
    pub fallback_port: u16,

    /// Connetion Mode:
    /// 
    /// - t (for tcp-tls)
    /// 
    /// - q (for quic)
    /// 
    /// - l (for lite-tls)
    #[cfg(feature = "client")]
    #[structopt(short = "m", long, default_value = "t", parse(from_str = parse_connection_mode))]
    pub connection_mode: ConnectionMode,
    
    #[cfg(feature = "server")]
    #[structopt(short = "n", long, default_value = "1.2")]
    pub latency_factor: f32,
   
    pub remote_socket_addr: Option<SocketAddr>,
}

#[cfg_attr(feature = "debug_info", derive(Debug))]
pub struct TrojanContext {
    pub options: Arc<Opt>,
    pub shutdown: broadcast::Receiver<()>,
}

impl TrojanContext {
    pub fn clone_with_signal(&self, shutdown: broadcast::Receiver<()>) -> Self {
        Self {
            options: self.options.clone(),
            shutdown,
        }
    }
}

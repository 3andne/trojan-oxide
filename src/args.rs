use crate::{protocol::HASH_LEN, utils::ConnectionMode};
use sha2::{Digest, Sha224};
use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;

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

fn parse_connection_mode(l: &str) -> ConnectionMode {
    match &l.to_lowercase()[..] {
        "tcp-tls" => ConnectionMode::TcpTLS,
        "t" => ConnectionMode::TcpTLS,
        "tcp" => ConnectionMode::TcpTLS,
        "tcp_tls" => ConnectionMode::TcpTLS,
        #[cfg(feature = "quic")]
        "quic" => ConnectionMode::Quic,
        #[cfg(feature = "quic")]
        "q" => ConnectionMode::Quic,
        _ => ConnectionMode::TcpTLS,
    }
}

fn parse_addr(l: &str) -> String {
    "127.0.0.1:".to_owned() + l
}

// fn parse_port(l: &str) -> u16 {
//     let mut res = 0;
//     for i in l.bytes() {
//         if i <= b'9' && i >= b'0' {
//             res = res * 10 + (i - b'0') as u16;
//         } else {
//             return 8889;
//         }
//     }
//     res
// }

fn password_to_hash(s: &str) -> Arc<String> {
    let mut hasher = Sha224::new();
    hasher.update(s);
    let h = hasher.finalize();
    let mut s = String::with_capacity(HASH_LEN);
    for i in h {
        write!(&mut s, "{:02x}", i).unwrap();
    }
    Arc::new(s)
}

fn arc_string(s: &str) -> Arc<String> {
    Arc::new(s.to_string())
}

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "basic")]
pub struct Opt {
    #[structopt(short = "h", long = "http_port", default_value = "8888", parse(from_str = parse_addr))]
    pub local_http_addr: String,

    #[structopt(short = "5", long = "socks5_port", default_value = "8889", parse(from_str = parse_addr))]
    pub local_socks5_addr: String,

    #[structopt(short = "l", long, default_value = "info", parse(from_str = parse_log_level))]
    pub log_level: tracing::Level,

    #[structopt(parse(from_os_str), long = "ca")]
    pub ca: Option<PathBuf>,

    #[structopt(short = "u", long, default_value = "localhost")]
    pub proxy_url: String,

    #[structopt(short = "x", long, default_value = "9999")]
    pub proxy_port: String,

    #[structopt(short, long)]
    pub server: bool,

    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    pub key: Option<PathBuf>,

    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    pub cert: Option<PathBuf>,

    #[structopt(short = "w", long, parse(from_str = password_to_hash))]
    pub password_hash: Arc<String>,

    #[structopt(short = "f", long, parse(from_str = arc_string))]
    pub fallback_port: Arc<String>,

    #[structopt(short = "m", long, default_value = "quic", parse(from_str = parse_connection_mode))]
    pub connection_mode: ConnectionMode,
}

#[derive(Debug, Clone)]
pub struct TrojanContext {
    pub options: Opt,
    pub remote_socket_addr: SocketAddr,
}

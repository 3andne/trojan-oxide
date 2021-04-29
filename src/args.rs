use sha2::{Digest, Sha224};
use std::fmt::Write;
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

fn parse_addr(l: &str) -> String {
    "127.0.0.1:".to_owned() + l
}

const HASH_LEN: usize = 56;

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

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
pub struct Opt {
    #[structopt(short = "p", long = "port", default_value = "8888", parse(from_str = parse_addr))]
    pub local_addr: String,

    #[structopt(short = "l", long, default_value = "info", parse(from_str = parse_log_level))]
    pub log_level: tracing::Level,

    #[structopt(parse(from_os_str), long = "ca")]
    pub ca: Option<PathBuf>,

    #[structopt(short, long, default_value = "localhost")]
    pub proxy_url: String,

    #[structopt(short, long, default_value = "8889", parse(from_str = parse_addr))]
    pub proxy_port: String,

    #[structopt(short, long)]
    pub server: bool,

    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    pub key: Option<PathBuf>,

    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    pub cert: Option<PathBuf>,

    #[structopt(short, long, parse(from_str = password_to_hash))]
    pub password_hash: Arc<String>,
}

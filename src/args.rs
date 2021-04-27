use std::path::PathBuf;
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
}

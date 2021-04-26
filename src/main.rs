#![feature(aarch64_target_feature)]
#![feature(stdsimd)]
mod server;
pub mod simd;

use anyhow::Result;
use clap::{App, Arg};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("proxx")
        .version("0.0.1")
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-level")
                .short("l")
                .long("log-level")
                .takes_value(true),
        )
        .get_matches();

    let addr = "127.0.0.1:".to_owned() + matches.value_of("port").unwrap_or("8888");
    let loglevel = matches
        .value_of("log-level")
        .map_or(tracing::Level::INFO, |f| match &f.to_lowercase()[..] {
            "info" => tracing::Level::INFO,
            "debug" => tracing::Level::DEBUG,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            "trace" => tracing::Level::TRACE,
            _ => tracing::Level::INFO,
        });

    let collector = tracing_subscriber::fmt().with_max_level(loglevel).finish();

    let _ = tracing::subscriber::set_global_default(collector);

    let addr = addr.parse::<SocketAddr>()?;
    let listener = TcpListener::bind(&addr).await?;
    let _ = server::start_server(listener, tokio::signal::ctrl_c()).await;
    Ok(())
}

// #![feature(aarch64_target_feature)]
// #![feature(stdsimd)]
mod proxy;
mod server;
// pub mod simd;

mod args;
use structopt::StructOpt;

mod client;
mod tunnel;
mod utils;

use anyhow::anyhow;
use anyhow::Result;
use std::net::ToSocketAddrs;
// use clap::{App, Arg};

#[tokio::main]
async fn main() -> Result<()> {
    let mut options = args::Opt::from_args();
    options.remote_socket_addr = (options.proxy_url.to_owned() + ":" + &options.proxy_port)
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow!("invalid remote address"))?;
    let collector = tracing_subscriber::fmt()
        .with_max_level(options.log_level)
        .finish();
    let _ = tracing::subscriber::set_global_default(collector);
    let _ = proxy::build_tunnel(tokio::signal::ctrl_c(), options).await;
    Ok(())
}

// #![feature(aarch64_target_feature)]
// #![feature(stdsimd)]
mod proxy;
mod server;
// pub mod simd;

mod args;
use structopt::StructOpt;

mod tunnel;
mod client;
mod utils;

use anyhow::Result;
// use clap::{App, Arg};

#[tokio::main]
async fn main() -> Result<()> {
    let opt = args::Opt::from_args();
    let collector = tracing_subscriber::fmt().with_max_level(opt.log_level).finish();

    let _ = tracing::subscriber::set_global_default(collector);
    let _ = proxy::build_tunnel(tokio::signal::ctrl_c(), opt).await;
    Ok(())
}

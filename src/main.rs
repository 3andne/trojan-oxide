#![feature(aarch64_target_feature)]
#![feature(stdsimd)]
mod server;
pub mod simd;

mod args;
use structopt::StructOpt;

mod quic_tunnel;

use anyhow::Result;
// use clap::{App, Arg};

#[tokio::main]
async fn main() -> Result<()> {
    let opt = args::Opt::from_args();
    let collector = tracing_subscriber::fmt().with_max_level(opt.log_level).finish();

    let _ = tracing::subscriber::set_global_default(collector);

    let _ = server::build_tunnel(tokio::signal::ctrl_c(), opt).await;
    Ok(())
}

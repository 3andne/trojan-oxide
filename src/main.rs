// #![feature(aarch64_target_feature)]
// #![feature(stdsimd)]
mod proxy;
mod server;
// pub mod simd;

mod args;
use args::{Opt, TrojanContext};
use structopt::StructOpt;

mod client;
mod tunnel;
mod utils;

use anyhow::anyhow;
use anyhow::Result;
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

#[tokio::main]
async fn main() -> Result<()> {
    let options = Opt::from_args();

    let collector = tracing_subscriber::fmt()
        .with_max_level(options.log_level)
        .finish();
    let (dns_resolve_task_tx, dns_resolve_task_rx) = mpsc::channel(10);
    let remote_socket_addr = (options.proxy_url.to_owned() + ":" + options.proxy_port.as_str())
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow!("invalid remote address"))?;
    let context = TrojanContext {
        options,
        remote_socket_addr,
        dns_resolve_tx: Arc::new(dns_resolve_task_tx),
    };

    tokio::spawn(crate::utils::dns_resolve::dns_tasks(dns_resolve_task_rx));

    let _ = tracing::subscriber::set_global_default(collector);
    let _ = proxy::build_tunnel(tokio::signal::ctrl_c(), context).await;
    Ok(())
}

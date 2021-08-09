// #![feature(aarch64_target_feature)]
// #![feature(stdsimd)]
#[cfg(feature = "client")]
mod client;
mod proxy;

mod protocol;
#[cfg(feature = "server")]
mod server;
// pub mod simd;

#[cfg(not(any(feature = "client", feature = "server")))]
mod must_choose_between_client_and_server;
#[cfg(not(any(feature = "quic", feature = "tcp_tls", feature = "lite_tls")))]
mod must_choose_between_quic_and_tcp_tls;

mod args;
use args::{Opt, TrojanContext};
use structopt::StructOpt;

mod utils;

use anyhow::anyhow;
use anyhow::Result;
use std::net::ToSocketAddrs;

#[cfg(feature = "lite_tls")]
use glommio::{Local, LocalExecutorBuilder};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    let options = Opt::from_args();

    let collector = tracing_subscriber::fmt()
        .with_max_level(options.log_level)
        .with_target(if cfg!(feature = "debug_info") {
            true
        } else {
            false
        })
        .finish();
    let remote_socket_addr = (if options.proxy_ip.len() > 0 {
        options.proxy_ip.to_owned()
    } else {
        options.proxy_url.to_owned()
    } + ":"
        + options.proxy_port.as_str())
    .to_socket_addrs()?
    .next()
    .ok_or(anyhow!("invalid remote address"))?;

    let context = if cfg!(target_os = "macos") {
        let numc = num_cpus::get();
        let tcp_submit = Vec::with_capacity(numc);
        for i in 0..numc {
            let (tcp_tx, tcp_rx) = mpsc::channel(100);
            tcp_submit.push(tcp_tx);
            std::thread::spawn(move || {
                let ex = LocalExecutorBuilder::new().pin_to_cpu(i).make().unwrap();
                ex.run(Local::local(async {
                    tcp_rx;
                    println!("polled");
                }))
            });
        }
        TrojanContext {
            options,
            remote_socket_addr,
            tcp_submit,
        }
    };

    let _ = tracing::subscriber::set_global_default(collector);
    let _ = proxy::build_tunnel(tokio::signal::ctrl_c(), context).await;
    Ok(())
}

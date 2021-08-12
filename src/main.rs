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

#[cfg(all(target_os = "linux", feature = "zio"))]
use {
    tokio::sync::OnceCell,
    utils::{start_tcp_relay_threads, TcpTx},
};

#[cfg(all(target_os = "linux", feature = "zio"))]
pub static VEC_TCP_TX: OnceCell<Vec<TcpTx>> = OnceCell::const_new();

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
    let _ = tracing::subscriber::set_global_default(collector);

    #[cfg(all(target_os = "linux", feature = "zio"))]
    {
        use tracing::info;
        let tcp_submit = start_tcp_relay_threads();
        let _ = VEC_TCP_TX.set(tcp_submit);
        info!("glommio runtime started");
    }

    let remote_socket_addr = (if options.proxy_ip.len() > 0 {
        options.proxy_ip.to_owned()
    } else {
        options.proxy_url.to_owned()
    } + ":"
        + options.proxy_port.as_str())
    .to_socket_addrs()?
    .next()
    .ok_or(anyhow!("invalid remote address"))?;

    let context = TrojanContext {
        options,
        remote_socket_addr,
    };

    let _ = proxy::build_tunnel(tokio::signal::ctrl_c(), context).await;
    Ok(())
}

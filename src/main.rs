// #![feature(aarch64_target_feature)]
// #![feature(stdsimd)]
#![feature(type_alias_impl_trait)]
#![feature(associated_type_defaults)]

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

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
use args::Opt;
mod utils;

use anyhow::{anyhow, Result};
use std::{net::ToSocketAddrs, sync::Arc};
use structopt::StructOpt;

#[cfg(all(target_os = "linux", feature = "zio"))]
use {
    tokio::sync::OnceCell,
    utils::{start_tcp_relay_threads, TcpTx},
};

#[cfg(all(target_os = "linux", feature = "zio"))]
pub static VEC_TCP_TX: OnceCell<Vec<TcpTx>> = OnceCell::const_new();

#[tokio::main]
async fn main() -> Result<()> {
    let mut options = Opt::from_args();
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

    options.remote_socket_addr = Some(
        (
            if options.server_ip.len() > 0 {
                options.server_ip.to_owned()
            } else {
                options.server_hostname.to_owned()
            },
            options.server_port,
        )
            .to_socket_addrs()?
            .next()
            .ok_or(anyhow!("invalid remote address"))?,
    );

    utils::start_dns_resolver_thread();
    utils::start_latency_estimator();

    let _ = proxy::build_tunnel(tokio::signal::ctrl_c(), Arc::new(options)).await;
    Ok(())
}

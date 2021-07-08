use anyhow::Result;
use std::net::IpAddr;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::*;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

use crate::or_continue;

pub async fn dns_tasks(
    mut incoming_tasks: mpsc::Receiver<(String, oneshot::Sender<Option<IpAddr>>)>,
) -> Result<()> {
    // let mut config = ResolverConfig::new();
    // config.add_name_server(NameServerConfig {
    //     socket_addr: ([127, 0, 0, 1], 5430).into(),
    //     protocol: Protocol::Udp,
    //     tls_dns_name: None,
    //     trust_nx_responses: true,
    // });
    let mut resolver_opt = ResolverOpts::default();
    resolver_opt.ip_strategy = LookupIpStrategy::Ipv4Only;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), resolver_opt)?;
    loop {
        let (task, ret) = match incoming_tasks.recv().await {
            Some(t) => t,
            None => {
                return Ok(());
            }
        };

        let response = or_continue!(resolver.lookup_ip(task).await);
        let mut add_ret = None;
        for address in response {
            if address.is_ipv4() {
                add_ret = Some(address);
                break;
            }
        }
        let _ = ret.send(add_ret);
    }
}

use super::inbound::{accept_http_request, accept_sock5_request, user_endpoint_listener};
use crate::args::TrojanContext;
use anyhow::Result;
use std::net::SocketAddr;
use tokio::sync::oneshot;

pub async fn run_client(
    upper_shutdown: oneshot::Receiver<()>,
    context: TrojanContext,
) -> Result<()> {
    // blocking by async in traits
    // trait ClientReqAcc { async fn accept(stream: TcpStream) -> ... }
    // impl ClientReqAcc for HttpAcc;
    // impl ClientReqAcc for Socks5Acc;
    // struct Listener<ClientReqAcc> { fn new(); async fn listen(); };
    //          listen(): user_endpoint_listener()
    // let http_listener = Listener::new::<HttpAcc>::();
    // let socks5_listener = Listener::new::<Socks5Acc>::();
    // http_listener.listen().await; socks5_listener.listen().await;

    // ClientServerConnection would be elimiated
    let http_addr = context.options.local_http_addr.parse::<SocketAddr>()?;
    let socks5_addr = context.options.local_socks5_addr.parse::<SocketAddr>()?;
    let (_shutdown1_tx, shutdown1_rx) = oneshot::channel();
    let (_shutdown2_tx, shutdown2_rx) = oneshot::channel();
    tokio::spawn(user_endpoint_listener(
        shutdown1_rx,
        http_addr,
        context.clone(),
        accept_http_request,
    ));

    tokio::spawn(user_endpoint_listener(
        shutdown2_rx,
        socks5_addr,
        context,
        accept_sock5_request,
    ));
    let _ = upper_shutdown.await;
    Ok(())
}

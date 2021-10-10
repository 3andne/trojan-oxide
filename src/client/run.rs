use super::inbound::{user_endpoint_listener, HttpRequest, Socks5Request};
use crate::args::TrojanContext;
use anyhow::Result;
use tokio::sync::broadcast;

pub async fn run_client(mut context: TrojanContext) -> Result<()> {
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
    let http_addr = context.options.local_http_addr;
    let socks5_addr = context.options.local_socks5_addr;
    let (shutdown_tx, shutdown) = broadcast::channel(1);
    tokio::spawn(user_endpoint_listener::<HttpRequest>(
        http_addr,
        context.clone_with_signal(shutdown),
    ));

    tokio::spawn(user_endpoint_listener::<Socks5Request>(
        socks5_addr,
        context.clone_with_signal(shutdown_tx.subscribe()),
    ));
    let _ = context.shutdown.recv().await;
    Ok(())
}

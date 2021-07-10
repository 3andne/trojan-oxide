use crate::utils::{
    copy_udp, new_trojan_udp_stream, ClientServerConnection, ClientTcpStream, Socks5UdpStream,
};
use tokio::{io::split, select, sync::broadcast};
use tracing::debug;

pub async fn relay_tcp(
    mut inbound: ClientTcpStream,
    outbound: ClientServerConnection,
    mut upper_shutdown: broadcast::Receiver<()>,
) {
    let (mut in_read, mut in_write) = inbound.split();
    match outbound {
        // ClientServerConnection::Quic((mut out_write, mut out_read)) => {
        //     select! {
        //         res = tokio::io::copy(&mut out_read, &mut in_write) => {
        //             debug!("tcp relaying download end, {:?}", res);
        //         },
        //         res = tokio::io::copy(&mut in_read, &mut out_write) => {
        //             debug!("tcp relaying upload end, {:?}", res);
        //         },
        //         _ = upper_shutdown.recv() => {
        //             debug!("shutdown signal received");
        //         },
        //     }
        // }
        ClientServerConnection::TcpTLS(out_tls) => {
            let (mut out_read, mut out_write) = split(out_tls);
            select! {
                res = tokio::io::copy(&mut out_read, &mut in_write) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = tokio::io::copy(&mut in_read, &mut out_write) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
        }
    }
}

pub async fn relay_udp(
    mut inbound: Socks5UdpStream,
    outbound: ClientServerConnection,
    mut upper_shutdown: broadcast::Receiver<()>,
) {
    let (mut in_write, mut in_read) = inbound.split();
    match outbound {
        // ClientServerConnection::Quic((out_write, out_read)) => {
        //     let (mut out_write, mut out_read) = new_trojan_udp_stream(out_write, out_read, None);
        //     select! {
        //         res = copy_udp(&mut out_read, &mut in_write) => {
        //             debug!("tcp relaying download end, {:?}", res);
        //         },
        //         res = copy_udp(&mut in_read, &mut out_write) => {
        //             debug!("tcp relaying upload end, {:?}", res);
        //         },
        //         _ = upper_shutdown.recv() => {
        //             debug!("shutdown signal received");
        //         },
        //     }
        // }
        ClientServerConnection::TcpTLS(out_tls) => {
            let (out_read, out_write) = split(out_tls);
            let (mut out_write, mut out_read) = new_trojan_udp_stream(out_write, out_read, None);
            select! {
                res = copy_udp(&mut out_read, &mut in_write) => {
                    debug!("tcp relaying download end, {:?}", res);
                },
                res = copy_udp(&mut in_read, &mut out_write) => {
                    debug!("tcp relaying upload end, {:?}", res);
                },
                _ = upper_shutdown.recv() => {
                    debug!("shutdown signal received");
                },
            }
        }
    }
}

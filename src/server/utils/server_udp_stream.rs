use crate::utils::{MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite, DNS_TX};
use futures::ready;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
#[cfg(feature = "udp_info")]
use tracing::*;

#[cfg_attr(feature = "debug_info", derive(Debug))]
pub struct ServerUdpStream {
    inner: Arc<UdpSocket>,
    addr_task: ResolveAddr,
}

impl ServerUdpStream {
    pub fn new(inner: UdpSocket) -> Self {
        Self {
            inner: Arc::new(inner),
            addr_task: ResolveAddr::None,
        }
    }
}

impl UdpWrite for ServerUdpStream {
    fn poll_proxy_stream_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>> {
        #[cfg(feature = "udp_info")]
        debug!("ServerUdpSendStream::poll_proxy_stream_write()");
        loop {
            match self.addr_task {
                ResolveAddr::Pending(ref mut task) => {
                    let ip = match task.try_recv() {
                        Ok(ip) => ip,
                        Err(TryRecvError::Empty) => return Poll::Pending,
                        Err(TryRecvError::Closed) => return Poll::Ready(Ok(0)),
                    };
                    self.addr_task = ResolveAddr::Ready((ip, addr.port()).into());
                }
                ResolveAddr::Ready(s_addr) => {
                    #[cfg(feature = "udp_info")]
                    debug!(
                        "ServerUdpSendStream::poll_proxy_stream_write() ResolveAddr::Ready({}), buf {:?}",
                        s_addr, buf
                    );

                    let res = self.inner.poll_send_to(cx, buf, s_addr);

                    if let Poll::Ready(Ok(val)) = res {
                        if val == buf.len() {
                            self.addr_task = ResolveAddr::None;
                        }
                    }
                    return res;
                }
                ResolveAddr::None => {
                    #[cfg(feature = "udp_info")]
                    debug!("ServerUdpSendStream::poll_proxy_stream_write() ResolveAddr::None");

                    use MixAddrType::*;
                    self.addr_task = match addr {
                        x @ V4(_) | x @ V6(_) => ResolveAddr::Ready(x.clone().to_socket_addrs()),
                        Hostname((name, _)) => {
                            let name = name.to_owned();
                            let (task_tx, task_rx) = oneshot::channel();
                            tokio::spawn(async move {
                                DNS_TX.get().unwrap().send((name, task_tx)).await
                            });
                            ResolveAddr::Pending(task_rx)
                        }
                        _ => panic!("unprecedented MixAddrType variant"),
                    };
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg_attr(feature = "debug_info", derive(Debug))]
enum ResolveAddr {
    Pending(oneshot::Receiver<IpAddr>),
    Ready(SocketAddr),
    None,
}

impl UdpRead for ServerUdpStream {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<MixAddrType>> {
        #[cfg(feature = "udp_info")]
        debug!("ServerUdpRecvStream::poll_proxy_stream_read()");

        let mut read_buf = buf.as_read_buf();
        let ptr = read_buf.filled().as_ptr();

        let addr = ready!(self.inner.poll_recv_from(cx, &mut read_buf))?;

        // Ensure the pointer does not change from under us
        assert_eq!(ptr, read_buf.filled().as_ptr());
        let n = read_buf.filled().len();

        if n == 0 {
            // EOF is seen
            return Poll::Ready(Ok(MixAddrType::None));
        }

        // Safety: This is guaranteed to be the number of initialized (and read)
        // bytes due to the invariants provided by `ReadBuf::filled`.
        unsafe {
            buf.advance_mut(n);
        }

        #[cfg(feature = "udp_info")]
        debug!(
            "ServerUdpRecvStream::poll_proxy_stream_read() buf {:?}",
            buf
        );

        Poll::Ready(Ok((&addr).into()))
    }
}

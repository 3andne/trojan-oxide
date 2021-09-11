use crate::utils::{MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite};
use futures::{ready, Future};
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::task::spawn_blocking;
use tokio::{net::UdpSocket, task::JoinHandle};
#[cfg(feature = "debug_info")]
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
        #[cfg(feature = "debug_info")]
        debug!("ServerUdpSendStream::poll_proxy_stream_write()");
        loop {
            match self.addr_task {
                ResolveAddr::Pending(ref mut task) => {
                    #[cfg(feature = "debug_info")]
                    debug!(
                        "ServerUdpSendStream::poll_proxy_stream_write() ResolveAddr::Pending({:?})",
                        task
                    );

                    let poll_res = Pin::new(task).poll(cx);

                    #[cfg(feature = "debug_info")]
                    debug!(
                        "ServerUdpSendStream::poll_proxy_stream_write() ResolveAddr::Pending(), res: {:?}",
                        poll_res
                    );

                    match ready!(poll_res)??.next() {
                        Some(x) => {
                            self.addr_task = ResolveAddr::Ready(x);
                        }
                        None => {
                            self.addr_task = ResolveAddr::None;
                            return Poll::Ready(Ok(0));
                        }
                    }
                }
                ResolveAddr::Ready(s_addr) => {
                    #[cfg(feature = "debug_info")]
                    debug!(
                        "ServerUdpSendStream::poll_proxy_stream_write() ResolveAddr::Ready({}), buf {:?}",
                        s_addr, buf
                    );

                    let res = self.inner.poll_send_to(cx, buf, s_addr);

                    if res.is_ready() {
                        self.addr_task = ResolveAddr::None;
                    }
                    return res;
                }
                ResolveAddr::None => {
                    #[cfg(feature = "debug_info")]
                    debug!("ServerUdpSendStream::poll_proxy_stream_write() ResolveAddr::None");

                    use MixAddrType::*;
                    self.addr_task = match addr {
                        x @ V4(_) | x @ V6(_) => ResolveAddr::Ready(x.clone().to_socket_addrs()),
                        Hostname((name, port)) => {
                            let name = name.to_owned();
                            let port = *port;
                            ResolveAddr::Pending(spawn_blocking(move || {
                                std::net::ToSocketAddrs::to_socket_addrs(&(name.as_str(), port))
                            }))
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
    Pending(JoinHandle<std::io::Result<vec::IntoIter<SocketAddr>>>),
    Ready(SocketAddr),
    None,
}

impl UdpRead for ServerUdpStream {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<std::io::Result<MixAddrType>> {
        #[cfg(feature = "debug_info")]
        debug!("ServerUdpRecvStream::poll_proxy_stream_read()");
        let mut buf_inner = buf.as_read_buf();
        let ptr = buf_inner.filled().as_ptr();

        let _ = ready!(self.inner.poll_recv_from(cx, &mut buf_inner))?;

        // Ensure the pointer does not change from under us
        assert_eq!(ptr, buf_inner.filled().as_ptr());
        let n = buf_inner.filled().len();

        if n == 0 {
            // EOF is seen
            return Poll::Ready(Ok(MixAddrType::None));
        }

        // Safety: This is guaranteed to be the number of initialized (and read)
        // bytes due to the invariants provided by `ReadBuf::filled`.
        unsafe {
            buf.advance_mut(n);
        }

        #[cfg(feature = "debug_info")]
        debug!(
            "ServerUdpRecvStream::poll_proxy_stream_read() buf {:?}",
            buf
        );

        Poll::Ready(Ok(MixAddrType::new_null()))
    }
}

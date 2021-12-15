use crate::utils::{MixAddrType, UdpRead, UdpRelayBuffer, UdpWrite, DNS_TX};
use futures::{ready, Future};
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
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
    ) -> Poll<Result<usize>> {
        mc::debug_info!(send self, "enter", "");
        loop {
            match self.addr_task {
                ResolveAddr::Pending((ref mut task, ref mut missed_wakeup)) => {
                    let ip = match Pin::new(task).poll(cx) {
                        Poll::Pending => {
                            *missed_wakeup = true;
                            mc::debug_info!(send self, "resolving pending & pending", "");
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(ip)) => {
                            if *missed_wakeup {
                                mc::debug_info!(send self, "adding back wakeups", "");
                                cx.waker().wake_by_ref();
                            }
                            ip
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(Ok(0)),
                    };
                    self.addr_task = ResolveAddr::Ready((ip, addr.port()).into());
                }
                ResolveAddr::Ready(s_addr) => {
                    let res = self.inner.poll_send_to(cx, buf, s_addr);

                    if let Poll::Ready(Ok(val)) = res {
                        if val == buf.len() {
                            self.addr_task = ResolveAddr::None;
                        }
                    }
                    mc::debug_info!(send self,
                        "ResolveAddr::Ready({})", format!("addr {:?} buf len {:?}, res {:?}", s_addr, buf.len(), res)
                    );
                    return res;
                }
                ResolveAddr::None => {
                    mc::debug_info!(send self, "ResolveAddr::None", "");

                    use MixAddrType::*;
                    self.addr_task = match addr {
                        x @ V4(_) | x @ V6(_) => ResolveAddr::Ready(x.clone().to_socket_addrs()),
                        Hostname((name, _)) => {
                            let name = name.to_owned();
                            let (task_tx, task_rx) = oneshot::channel();
                            tokio::spawn(async move {
                                DNS_TX.get().unwrap().send((name, task_tx)).await
                            });
                            ResolveAddr::Pending((task_rx, false))
                        }
                        _ => panic!("unprecedented MixAddrType variant"),
                    };
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg_attr(feature = "debug_info", derive(Debug))]
enum ResolveAddr {
    Pending((oneshot::Receiver<IpAddr>, bool)),
    Ready(SocketAddr),
    None,
}

impl UdpRead for ServerUdpStream {
    fn poll_proxy_stream_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut UdpRelayBuffer,
    ) -> Poll<Result<MixAddrType>> {
        mc::debug_info!(recv self, "enter", format!("buf len {}", buf.len()));

        let mut read_buf = buf.as_read_buf();

        let addr = ready!(self.inner.poll_recv_from(cx, &mut read_buf))?;

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

        mc::debug_info!(recv self, "read ok", format!("buf len {}, n {}", buf.len(), n));

        Poll::Ready(Ok((&addr).into()))
    }
}

mod mc {
    macro_rules! debug_info {
        (recv $me:expr, $msg:expr, $addition:expr) => {
            #[cfg(feature = "udp_info")]
            debug!("ServerUdpRecv {} | {:?}", $msg, $addition);
        };

        (send $me:expr, $msg:expr, $addition:expr) => {
            #[cfg(feature = "udp_info")]
            debug!("ServerUdpSend {} | {:?}", $msg, $addition,);
        };
    }
    pub(crate) use debug_info;
}

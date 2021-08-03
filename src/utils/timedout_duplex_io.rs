use futures::Future;
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    sync::atomic::{AtomicU32, Ordering},
    sync::Arc,
    task::Poll,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{sleep_until, Duration, Instant, Sleep},
};

#[cfg(feature = "udp")]
use crate::utils::MixAddrType;

#[cfg(feature = "udp")]
use super::{UdpRead, UdpWrite};

pin_project! {
    pub struct TimeoutMonitor {
        created: Instant,
        last_active: Arc<AtomicU32>,
        deadline: u32,
        #[pin]
        sleep: Sleep,
    }
}

pub struct TimedoutIO<R> {
    inner: R,
    created: Instant,
    last_active: Arc<AtomicU32>,
}

impl TimeoutMonitor {
    pub fn new(deadline: Duration) -> Self {
        let sleep = Instant::now() + deadline;
        Self {
            created: Instant::now(),
            last_active: Arc::new(AtomicU32::new(0)),
            deadline: deadline.as_secs() as u32,
            sleep: sleep_until(sleep),
        }
    }

    pub fn watch<R>(&self, inner: R) -> TimedoutIO<R> {
        TimedoutIO {
            inner,
            created: self.created,
            last_active: self.last_active.clone(),
        }
    }
}

impl Future for TimeoutMonitor {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        match me.sleep.as_mut().poll(cx) {
            Poll::Ready(()) => {
                let instant = Instant::now();
                let time_elapsed = (instant - *me.created).as_secs() as u32;
                let last_active = me.last_active.load(Ordering::Relaxed);
                let inactive_time = time_elapsed - last_active;
                if inactive_time > *me.deadline {
                    Poll::Ready(())
                } else {
                    me.sleep
                        .as_mut()
                        .reset(instant + Duration::from_secs(*me.deadline as u64));
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

macro_rules! poll_timeout {
    {With $me:expr, $poll:expr} => {
        match $poll {
            res @ Poll::Ready(_) => {
                let last_active = (Instant::now() - $me.created).as_secs() as u32;
                $me.last_active.store(last_active, Ordering::Relaxed);
                return res;
            },
            Poll::Pending => Poll::Pending,
        }
    };
}

#[cfg(feature = "udp")]
impl<T: UdpRead + Unpin> UdpRead for TimedoutIO<T> {
    fn poll_proxy_stream_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut super::UdpRelayBuffer,
    ) -> Poll<std::io::Result<crate::utils::MixAddrType>> {
        poll_timeout! {
            With self,
            Pin::new(&mut self.inner).poll_proxy_stream_read(cx, buf)
        }
    }
}

#[cfg(feature = "udp")]
impl<T: UdpWrite + Unpin> UdpWrite for TimedoutIO<T> {
    fn poll_proxy_stream_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        addr: &MixAddrType,
    ) -> Poll<std::io::Result<usize>> {
        poll_timeout! {
            With self,
            Pin::new(&mut self.inner).poll_proxy_stream_write(cx, buf, addr)
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        todo!()
    }

}

impl<T: AsyncRead + Unpin> AsyncRead for TimedoutIO<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        poll_timeout! {
            With self,
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TimedoutIO<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        poll_timeout! {
            With self,
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

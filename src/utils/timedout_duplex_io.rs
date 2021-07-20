use futures::Future;
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    sync::atomic::{AtomicU32, Ordering},
    task::Poll,
};

use tokio::time::{sleep_until, Duration, Instant, Sleep};

use crate::utils::MixAddrType;

use super::UdpRead;

pub struct TimedoutReadWrite<T> {
    inner: T,
    created: Instant,
    last_active: AtomicU32,
    deadline: Duration,
}

pin_project! {
    pub struct TimedoutRead<'a, R> {
        #[pin]
        inner: R,
        created: &'a Instant,
        last_active: &'a AtomicU32,
        #[pin]
        sleep: Sleep,
        deadline: u32,
    }
}

pub struct TimedoutWrite<'a, W> {
    inner: W,
    created: &'a Instant,
    last_active: &'a AtomicU32,
    sleep: Sleep,
    deadline: u32,
}

pub trait SplitIntoReadWrite {
    type R;
    type W;
    fn split(&self) -> (Self::R, Self::W);
}

impl<T> TimedoutReadWrite<T>
where
    T: SplitIntoReadWrite,
{
    fn split(&self) -> (TimedoutRead<T::R>, TimedoutWrite<T::W>) {
        let (r, w) = self.inner.split();
        let sleep = Instant::now() + self.deadline;
        (
            TimedoutRead {
                inner: r,
                created: &self.created,
                last_active: &self.last_active,
                deadline: self.deadline.as_secs() as u32,
                sleep: sleep_until(sleep),
            },
            TimedoutWrite {
                inner: w,
                created: &self.created,
                last_active: &self.last_active,
                deadline: self.deadline.as_secs() as u32,
                sleep: sleep_until(sleep),
            },
        )
    }
}

impl<T: UdpRead + Unpin> UdpRead for TimedoutRead<'_, T> {
    fn poll_proxy_stream_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut super::UdpRelayBuffer,
    ) -> Poll<std::io::Result<crate::utils::MixAddrType>> {
        let mut me = self.project();

        match me.inner.poll_proxy_stream_read(cx, buf) {
            res @ Poll::Ready(_) => {
                let last_active = (Instant::now() - **me.created).as_secs() as u32;
                me.last_active.store(last_active, Ordering::SeqCst);
                return res;
            }
            Poll::Pending => (),
        }

        match me.sleep.as_mut().poll(cx) {
            Poll::Ready(()) => {
                let instant = Instant::now();
                let time_elapsed = (instant - **me.created).as_secs() as u32;
                let last_active = me.last_active.load(Ordering::SeqCst);
                let inactive_time = time_elapsed - last_active;
                if inactive_time > *me.deadline {
                    Poll::Ready(Ok(MixAddrType::None))
                } else {
                    me.sleep.as_mut()
                        .reset(instant + Duration::from_secs(*me.deadline as u64));
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

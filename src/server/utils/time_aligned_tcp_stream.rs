use std::{
    io::Result,
    pin::Pin,
    sync::atomic::Ordering,
    task::{ready, Poll},
    time::Duration,
};

use futures::Future;
use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{sleep, Instant, Sleep},
};

use crate::utils::LATENCY_EST;

enum Stage {
    Read,
    Sleep,
}

pin_project! {
    pub struct TimeAlignedTcpStream<T> {
        #[pin]
        inner: T,
        outbound_rtt_ms: u32,
        enable: bool,
        stage: Stage,
        sleep: Pin<Box<Sleep>>,
        res: Option<Result<()>>,
    }
}

impl<T> TimeAlignedTcpStream<T> {
    pub fn new(inner: T) -> Self {
        let outbound_rtt_ms = LATENCY_EST.load(Ordering::Acquire);
        Self {
            inner,
            outbound_rtt_ms,
            enable: true,
            stage: Stage::Read,
            sleep: Box::pin(sleep(Duration::from_millis(outbound_rtt_ms as u64))),
            res: None,
        }
    }

    pub fn disable_time_alignment(&mut self) {
        self.enable = false;
    }

    pub(crate) fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimeAlignedTcpStream<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<Result<()>> {
        let me = self.project();
        if !*me.enable {
            me.inner.poll_read(cx, buf)
        } else {
            match me.stage {
                Stage::Read => {
                    *me.res = Some(ready!(me.inner.poll_read(cx, buf)));
                    *me.stage = Stage::Sleep;
                    me.sleep
                        .as_mut()
                        .reset(Instant::now() + Duration::from_millis(*me.outbound_rtt_ms as u64));
                    ready!(me.sleep.as_mut().poll(cx));
                    Poll::Pending
                }
                Stage::Sleep => {
                    ready!(me.sleep.as_mut().poll(cx));
                    *me.stage = Stage::Read;
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

impl<T: AsyncWrite> AsyncWrite for TimeAlignedTcpStream<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let me = self.project();
        me.inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<()>> {
        let me = self.project();
        me.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<()>> {
        let me = self.project();
        me.inner.poll_shutdown(cx)
    }
}

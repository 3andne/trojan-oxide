use std::pin::Pin;
use std::{fmt::Debug, task::Poll};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

#[derive(Debug)]
pub struct DebugAsyncReader<T> {
    inner: T,
    pending_times: usize,
}

impl<T> DebugAsyncReader<T> {
    pub fn new(inner: T) -> DebugAsyncReader<T> {
        Self {
            inner,
            pending_times: 0,
        }
    }
}

impl<T> AsyncRead for DebugAsyncReader<T>
where
    T: AsyncRead + Unpin + Debug,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            res @ Poll::Ready(_) => {
                self.pending_times = 0;
                res
            }
            res @ Poll::Pending => {
                self.pending_times += 1;
                debug!("self: {:?}", &self);
                res
            }
        }
    }
}

#[derive(Debug)]
pub struct DebugAsyncWriter<T> {
    inner: T,
    pending_times: usize,
}

impl<T> DebugAsyncWriter<T> {
    pub fn new(inner: T) -> DebugAsyncWriter<T> {
        Self {
            inner,
            pending_times: 0,
        }
    }
}

impl<T> AsyncWrite for DebugAsyncWriter<T>
where
    T: AsyncWrite + Unpin + Debug,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            res @ Poll::Ready(_) => {
                self.pending_times = 0;
                res
            }
            res @ Poll::Pending => {
                self.pending_times += 1;
                debug!("self: {:?}", &self);
                res
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            res @ Poll::Ready(_) => {
                self.pending_times = 0;
                res
            }
            res @ Poll::Pending => {
                self.pending_times += 1;
                debug!("self: {:?}", &self);
                res
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            res @ Poll::Ready(_) => {
                self.pending_times = 0;
                res
            }
            res @ Poll::Pending => {
                self.pending_times += 1;
                debug!("self: {:?}", &self);
                res
            }
        }
    }
}

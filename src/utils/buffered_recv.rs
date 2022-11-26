use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg_attr(feature = "debug_info", derive(Debug))]
pub struct BufferedRecv<T> {
    buffered_request: Option<(usize, Vec<u8>)>,
    inner: T,
}

impl<T> BufferedRecv<T> {
    pub fn new(inner: T, buffered_request: Option<(usize, Vec<u8>)>) -> Self {
        Self {
            inner,
            buffered_request,
        }
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> (T, Option<(usize, Vec<u8>)>) {
        (self.inner, self.buffered_request)
    }
}

impl<T> AsyncRead for BufferedRecv<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.buffered_request.is_some() {
            let (index, buffered_request) = self.buffered_request.as_ref().unwrap();
            buf.put_slice(&buffered_request[*index..]);
            self.buffered_request = None;
            return Poll::Ready(Ok(()));
        }

        let reader = Pin::new(&mut self.inner);
        reader.poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for BufferedRecv<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
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

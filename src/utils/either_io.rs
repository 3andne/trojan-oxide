use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

pub enum EitherIO<IO1, IO2> {
    Left(IO1),
    Right(IO2),
}

impl<IO1, IO2> AsyncWrite for EitherIO<IO1, IO2>
where
    IO1: AsyncWrite + Unpin,
    IO2: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match *self {
            EitherIO::Left(ref mut io) => Pin::new(io).poll_write(cx, buf),
            EitherIO::Right(ref mut io) => Pin::new(io).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match *self {
            EitherIO::Left(ref mut io) => Pin::new(io).poll_flush(cx),
            EitherIO::Right(ref mut io) => Pin::new(io).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match *self {
            EitherIO::Left(ref mut io) => Pin::new(io).poll_shutdown(cx),
            EitherIO::Right(ref mut io) => Pin::new(io).poll_shutdown(cx),
        }
    }
}

impl<IO1, IO2> AsyncRead for EitherIO<IO1, IO2>
where
    IO1: AsyncRead + Unpin,
    IO2: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match *self {
            EitherIO::Left(ref mut io) => Pin::new(io).poll_read(cx, buf),
            EitherIO::Right(ref mut io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}

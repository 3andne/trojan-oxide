use std::{pin::Pin, task::Poll};

use crate::utils::VecAsReadBufExt;
use futures::ready;
use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

pub enum LiteStreams {
    TLS(TlsStream<TcpStream>),
    TCP(TcpStream),
}

enum LiteStreamState {}

pin_project! {
    pub struct ClientLiteStream {
        #[pin]
        inner: LiteStreams,
        state: LiteStreamState,
        buf: Vec<u8>,
        cursor: usize,
    }
}
impl AsyncRead for ClientLiteStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut me = self.project();
        match *me.inner {
            LiteStreams::TLS(ref mut tls) => {
                let mut buf_inner = me.buf.as_read_buf(*me.cursor);
                let ptr = buf_inner.filled().as_ptr();
                let _ = ready!(Pin::new(tls).poll_read(cx, &mut buf_inner))?;

                // Ensure the pointer does not change from under us
                assert_eq!(ptr, buf_inner.filled().as_ptr());
                let n = buf_inner.filled().len();

                if n == 0 {
                    // EOF is seen
                    return Poll::Ready(Ok(()));
                }
                todo!()
            }
            LiteStreams::TCP(ref tcp) => todo!(),
        }
        // let me = self.project();
        // me.inner.poll_read(cx, &mut buf_inner);
    }
}

impl AsyncWrite for ClientLiteStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

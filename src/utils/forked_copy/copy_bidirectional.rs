use super::CopyBuffer;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::utils::StreamStopReasons;
use futures::ready;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

struct CopyBidirectional<'a, I, O> {
    i: &'a mut I,
    o: &'a mut O,
    upload: TransferState,
    download: TransferState,
    stop_reason: StreamStopReasons,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running(buf) => {
                let count = ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => {
                ready!(w.as_mut().poll_shutdown(cx))?;

                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

impl<'a, I, O> Future for CopyBidirectional<'a, I, O>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<StreamStopReasons, (StreamStopReasons, std::io::Error)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        use StreamStopReasons::*;
        let CopyBidirectional {
            i,
            o,
            upload,
            download,
            stop_reason,
        } = &mut *self;

        let upload =
            transfer_one_direction(cx, upload, &mut *i, &mut *o).map_err(|e| (Upload, e))?;
        let download =
            transfer_one_direction(cx, download, &mut *o, &mut *i).map_err(|e| (Download, e))?;

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll
        use Poll::*;
        match (upload, download) {
            (Pending, Pending) => Pending,
            (Ready(_), Pending) => {
                *stop_reason = Upload;
                Pending
            }
            (Pending, Ready(_)) => {
                *stop_reason = Download;
                Pending
            }
            (Ready(_), Ready(_)) => Ready(Ok(stop_reason.clone())),
        }
    }
}

pub async fn copy_bidirectional_forked<I, O>(
    inbound: &mut I,
    outbound: &mut O,
) -> Result<StreamStopReasons, (StreamStopReasons, std::io::Error)>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    CopyBidirectional {
        i: inbound,
        o: outbound,
        upload: TransferState::Running(CopyBuffer::new()),
        download: TransferState::Running(CopyBuffer::new()),
        stop_reason: StreamStopReasons::Download,
    }
    .await
}

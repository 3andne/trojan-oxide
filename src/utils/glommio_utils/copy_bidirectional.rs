/// this is a replica of tokio::io::copy_bidirectional
/// but based on `futures` traits
use super::copy_buf::CopyBuffer;

use futures::{ready, AsyncRead, AsyncWrite};

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::utils::StreamStopReasons;

use tracing::debug;

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
    stop_reason: Option<StreamStopReasons>,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running(buf) => {
                debug!("transfer_one_direction: running");
                let count = ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => {
                debug!("transfer_one_direction: ShuttingDown");
                ready!(w.as_mut().poll_close(cx))?;

                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64, StreamStopReasons)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
            stop_reason,
        } = &mut *self;

        let a_to_b = transfer_one_direction(cx, a_to_b, &mut *a, &mut *b)?;
        let b_to_a = transfer_one_direction(cx, b_to_a, &mut *b, &mut *a)?;

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll
        use Poll::*;
        use StreamStopReasons::*;
        match (a_to_b, b_to_a) {
            (Pending, Pending) => Pending,
            (Ready(_a_to_b), Pending) => {
                *stop_reason = Some(Upload);
                Pending
            }
            (Pending, Ready(_b_to_a)) => {
                *stop_reason = Some(Download);
                Pending
            }
            (Ready(a_to_b), Ready(b_to_a)) => {
                if stop_reason.is_none() {
                    *stop_reason = Some(Download)
                }
                Ready(Ok((a_to_b, b_to_a, stop_reason.clone().unwrap())))
            }
        }
    }
}

pub async fn glommio_copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
) -> Result<(u64, u64, StreamStopReasons), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(CopyBuffer::new()),
        b_to_a: TransferState::Running(CopyBuffer::new()),
        stop_reason: None,
    }
    .await
}

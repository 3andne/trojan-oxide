use crate::utils::StreamStopReasons;
use crate::utils::{UdpCopyBuf, UdpRead, UdpWrite};
use futures::{ready, Future};
use std::pin::Pin;
use std::task::{Context, Poll};

enum TransferState {
    Running(UdpCopyBuf),
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
) -> Poll<std::io::Result<u64>>
where
    A: UdpRead + Unpin,
    B: UdpWrite + Unpin,
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

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: UdpRead + UdpWrite + Unpin,
    B: UdpRead + UdpWrite + Unpin,
{
    type Output = std::io::Result<(u64, u64, StreamStopReasons)>;

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

        let upload = transfer_one_direction(cx, upload, *i, *o)?;
        let download = transfer_one_direction(cx, download, *o, *i)?;

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll
        use Poll::*;
        match (upload, download) {
            (Pending, Pending) => Pending,
            (Ready(_upload), Pending) => {
                *stop_reason = Upload;
                Pending
            }
            (Pending, Ready(_download)) => {
                *stop_reason = Download;
                Pending
            }
            (Ready(upload), Ready(download)) => Ready(Ok((upload, download, stop_reason.clone()))),
        }
    }
}

pub async fn udp_copy_bidirectional<I, O>(
    inbound: &mut I,
    outbound: &mut O,
    conn_id: usize,
) -> Result<(u64, u64, StreamStopReasons), std::io::Error>
where
    I: UdpRead + UdpWrite + Unpin,
    O: UdpRead + UdpWrite + Unpin,
{
    CopyBidirectional {
        i: inbound,
        o: outbound,
        upload: TransferState::Running(UdpCopyBuf::new(Some(conn_id))),
        download: TransferState::Running(UdpCopyBuf::new(None)),
        stop_reason: StreamStopReasons::Download,
    }
    .await
}

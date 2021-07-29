use std::mem::MaybeUninit;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use anyhow::Result;

const RELAY_BUFFER_SIZE: usize = 8192;
pub async fn copy_to_tls<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
) -> Result<()> {
    // safety: We don't realy care what's previouly in the buffer
    let mut buf = unsafe {
        let buf: [MaybeUninit<u8>; RELAY_BUFFER_SIZE] = MaybeUninit::uninit().assume_init();
        std::mem::transmute::<_, [u8; RELAY_BUFFER_SIZE]>(buf)
    };

    loop {
        let len = r.read(&mut buf).await?;
        if len == 0 {
            return Ok(());
        }
        // let mut writen = 0;
        w.write(&buf[..len]).await?;
        // loop {
        //     writen += w.write(&buf[writen..len]).await?;
        //     if writen == len {
        //         break;
        //     }
        // }
        if len != buf.len() {
            w.flush().await?;
        }
    }
}

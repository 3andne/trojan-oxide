use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use anyhow::Result;

const RELAY_BUFFER_SIZE: usize = 2048;
pub async fn copy_tcp<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
) -> Result<()> {
    let mut buf = [0; RELAY_BUFFER_SIZE];
    loop {
        let len = r.read(&mut buf).await?;
        if len == 0 {
            return Ok(());
        }
        w.write(&buf[..len]).await?;
        if len != buf.len() {
            w.flush().await?;
        }
    }
}

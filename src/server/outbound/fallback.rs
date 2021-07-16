use std::{io::Cursor, sync::Arc};

use crate::utils::copy_tcp;
use anyhow::{anyhow, Context, Error, Result};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    select,
};
use tracing::*;

pub async fn fallback<IR: AsyncRead + Unpin, IW: AsyncWrite + Unpin>(
    buf: Vec<u8>,
    fallback_port: Arc<String>,
    mut in_read: IR,
    mut in_write: IW,
) -> Result<()> {
    let mut outbound = TcpStream::connect("127.0.0.1:".to_owned() + fallback_port.as_str())
        .await
        .map_err(|e| Error::new(e))
        .with_context(|| anyhow!("failed to connect to fallback service"))?;

    outbound
        .write_all_buf(&mut Cursor::new(&buf))
        .await
        .with_context(|| anyhow!("failed to write to fallback service"))?;

    let (mut out_read, mut out_write) = outbound.split();

    select! {
        res = copy_tcp(&mut out_read, &mut in_write) => {
            debug!("[fallback]relaying download end, {:?}", res);
        },
        res = tokio::io::copy(&mut in_read, &mut out_write) => {
            debug!("[fallback]relaying upload end, {:?}", res);
        },
    }
    Ok(())
}

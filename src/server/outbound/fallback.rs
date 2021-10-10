use std::{io::Cursor, net::IpAddr};

use crate::utils::copy_forked;
use anyhow::{anyhow, Context, Error, Result};
use tokio::{
    io::{split, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    select,
};
use tracing::*;

pub async fn fallback<I: AsyncRead + AsyncWrite + Unpin>(
    buf: Vec<u8>,
    fallback_port: u16,
    inbound: I,
) -> Result<()> {
    let mut outbound = TcpStream::connect((IpAddr::from([127, 0, 0, 1]), fallback_port))
        .await
        .map_err(|e| Error::new(e))
        .with_context(|| anyhow!("failed to connect to fallback service"))?;

    outbound
        .write_all_buf(&mut Cursor::new(&buf))
        .await
        .with_context(|| anyhow!("failed to write to fallback service"))?;

    let (mut out_read, mut out_write) = outbound.split();
    let (mut in_read, mut in_write) = split(inbound);
    select! {
        res = copy_forked(&mut out_read, &mut in_write) => {
            debug!("[fallback]relaying download end, {:?}", res);
        },
        res = copy_forked(&mut in_read, &mut out_write) => {
            debug!("[fallback]relaying upload end, {:?}", res);
        },
    }
    Ok(())
}

use std::{io::Cursor, sync::Arc};

use crate::utils::copy_tcp;
use anyhow::Result;
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
    let mut outbound = TcpStream::connect("127.0.0.1:".to_owned() + fallback_port.as_str()).await?;
    outbound.write_all_buf(&mut Cursor::new(&buf)).await?;

    let (mut out_read, mut out_write) = outbound.split();

    select! {
        res = copy_tcp(&mut out_read, &mut in_write) => {
            debug!("tcp relaying download end, {:?}", res);
        },
        res = tokio::io::copy(&mut in_read, &mut out_write) => {
            debug!("tcp relaying upload end, {:?}", res);
        },
    }
    Ok(())
}

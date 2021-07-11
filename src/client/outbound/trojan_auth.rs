use crate::{
    protocol::HASH_LEN,
    utils::{ClientServerConnection, MixAddrType},
};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

pub async fn trojan_auth_udp(
    outbound: &mut ClientServerConnection,
    password: Arc<String>,
) -> Result<()> {
    let addr = MixAddrType::V4(([0, 0, 0, 0], 0));
    match outbound {
        #[cfg(feature = "quic")]
        ClientServerConnection::Quic((out_write, _)) => {
            trojan_auth(true, &addr, out_write, password).await
        }
        ClientServerConnection::TcpTLS(out_write) => {
            trojan_auth(true, &addr, out_write, password).await
        }
    }
}

pub async fn trojan_auth_tcp(
    addr: &MixAddrType,
    outbound: &mut ClientServerConnection,
    password: Arc<String>,
) -> Result<()> {
    match outbound {
        #[cfg(feature = "quic")]
        ClientServerConnection::Quic((out_write, _)) => {
            trojan_auth(false, addr, out_write, password).await
        }
        ClientServerConnection::TcpTLS(out_write) => {
            trojan_auth(false, addr, out_write, password).await
        }
    }
}

async fn trojan_auth<A>(
    udp: bool,
    addr: &MixAddrType,
    outbound: &mut A,
    password: Arc<String>,
) -> Result<()>
where
    A: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = Vec::with_capacity(HASH_LEN + 2 + 1 + addr.encoded_len() + 2);
    buf.extend_from_slice(password.as_bytes());
    buf.extend_from_slice(&[b'\r', b'\n', if udp { 0x03 } else { 0x01 }]);
    addr.write_buf(&mut buf);
    buf.extend_from_slice(&[b'\r', b'\n']);
    trace!("trojan_connect: writing {:?}", buf);
    outbound.write_all(&buf).await?;
    // not using the following code because of quinn's bug.
    // let packet0 = [
    //     IoSlice::new(password_hash.as_bytes()),
    //     IoSlice::new(&command0[..command0_len]),
    //     IoSlice::new(self.host.as_bytes()),
    //     IoSlice::new(&port_arr),
    //     IoSlice::new(&[b'\r', b'\n']),
    // ];
    // let mut writer = Pin::new(outbound);
    // future::poll_fn(|cx| writer.as_mut().poll_write_vectored(cx, &packet0[..]))
    //     .await
    //     .map_err(|e| Box::new(e))?;

    // writer.flush().await.map_err(|e| Box::new(e))?;
    outbound.flush().await?;
    debug!("trojan packet 0 sent");

    Ok(())
}

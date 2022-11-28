use tokio::io::{AsyncRead, AsyncWrite};

use crate::utils::lite_tls::LeaveTls;

use super::trojan_inbound_callback::TrojanInboundCallback;

pub trait InboundStream:
    AsyncRead + AsyncWrite + LeaveTls + TrojanInboundCallback + Unpin + Send + 'static
{
}

impl<T: AsyncRead + AsyncWrite + LeaveTls + TrojanInboundCallback + Unpin + Send + 'static>
    InboundStream for T
{
}

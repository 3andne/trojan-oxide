use crate::{
    client::utils::{ClientConnectionRequest, ClientServerConnection},
    protocol::{ECHO_REQUEST_CMD, LITE_TLS_REQUEST_CMD, TCP_REQUEST_CMD, UDP_REQUEST_CMD},
    utils::ConnectionRequest,
};
pub struct ClientRequestCMD<'a>(
    pub &'a ClientConnectionRequest,
    pub &'a ClientServerConnection,
);

impl<'a> ClientRequestCMD<'a> {
    pub fn get_cmd(&self) -> u8 {
        use ClientServerConnection::*;
        use ConnectionRequest::*;
        match (self.0, self.1) {
            #[cfg(feature = "udp")]
            (UDP(_), _) => UDP_REQUEST_CMD,
            #[cfg(feature = "quic")]
            (ECHO(_), _) => ECHO_REQUEST_CMD,
            (TCP(_), LiteTLS(_)) => LITE_TLS_REQUEST_CMD,
            (TCP(_), _) => TCP_REQUEST_CMD,
            _ => unreachable!(),
        }
    }
}

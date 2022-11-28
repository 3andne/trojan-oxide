use crate::utils::WRTuple;

use super::time_aligned_tcp_stream::TimeAlignedTcpStream;

pub trait TrojanInboundCallback {
    fn handshake_finished(&mut self);
}

impl TrojanInboundCallback for WRTuple<quinn::SendStream, quinn::RecvStream> {
    fn handshake_finished(&mut self) {}
}

impl<T> TrojanInboundCallback for TimeAlignedTcpStream<T> {
    fn handshake_finished(&mut self) {
        self.disable_time_alignment()
    }
}

impl<T: TrojanInboundCallback> TrojanInboundCallback for tokio_rustls::server::TlsStream<T> {
    fn handshake_finished(&mut self) {
        self.get_mut().0.handshake_finished();
    }
}

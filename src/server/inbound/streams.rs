#[cfg(feature = "udp")]
use crate::utils::{TrojanUdpRecvStream, TrojanUdpSendStream};
use quinn::*;

#[cfg(feature = "quic")]
#[derive(Debug)]
pub struct QuicStream(pub(super) RecvStream, pub(super) SendStream);

#[cfg(feature = "udp")]
pub type TrojanUdpStream<W, R> = (TrojanUdpSendStream<W>, TrojanUdpRecvStream<R>);

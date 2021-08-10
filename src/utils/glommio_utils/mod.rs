mod copy_bidirectional;
mod copy_buf;
mod start_tcp_relay_thread;

use tokio::sync::oneshot;
use crate::utils::StreamStopReasons;

pub use start_tcp_relay_thread::start_tcp_relay_threads;
pub type TcpTaskRet = oneshot::Sender<StreamStopReasons>;
pub type TcpTx = tokio::sync::mpsc::Sender<(i32, i32, TcpTaskRet)>;
pub type TcpRx = tokio::sync::mpsc::Receiver<(i32, i32, TcpTaskRet)>;
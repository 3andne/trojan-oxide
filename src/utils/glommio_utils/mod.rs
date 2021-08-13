mod copy_bidirectional;
mod copy_buf;
mod start_tcp_relay_thread;

use std::net::TcpStream;

pub use start_tcp_relay_thread::start_tcp_relay_threads;
pub type TcpTx = tokio::sync::mpsc::Sender<(TcpStream, TcpStream, usize)>;
pub type TcpRx = tokio::sync::mpsc::Receiver<(TcpStream, TcpStream, usize)>;

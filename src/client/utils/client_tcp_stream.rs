use crate::utils::BufferedRecv;
use tokio::net::TcpStream;

pub fn new_client_tcp_stream(
    inner: TcpStream,
    http_request_extension: Option<Vec<u8>>,
) -> BufferedRecv<TcpStream> {
    BufferedRecv::new(inner, http_request_extension.map(|v| (0, v)))
}

#![feature(aarch64_target_feature)]
#![feature(stdsimd)]
pub mod simd;
use simd::simd_parse::*;
// use async_std::{
//     io::BufReader,
//     net::{TcpListener, TcpStream, ToSocketAddrs},
//     prelude::*,
//     task,
// };

// use hyper::*;

// type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
// fn main() {
//     let _ = task::block_on(start_server());
// }

// async fn start_server() -> Result<()> {
//     let addr = "127.0.0.1:7788";
//     let listener = TcpListener::bind(addr).await?;
//     let mut incoming = listener.incoming();
//     while let Some(stream) = incoming.next().await {
//         let stream = stream?;
//         println!("Accepting from: {}", stream.peer_addr()?);
//         task::spawn(async { connection_loop(stream) });
//     }
//     unimplemented!()
// }

// fn connection_loop(_: TcpStream) {
//     println!("stream acc");
// }

fn main() {
    let test = [
        b'_', b'_', b'_', b'_', b'_', b'_', b'_', b'_', b'_', b'_', b'\r', b'\n', b'_', b'_', b'_',
        b'_',
    ];

    let t1 = simd8_wrap(&test);
    let t2 = simd16_wrap(&test);
    let t3 = parse_scalar(&test);

    println!("{}, {}, {}", t1, t2, t3);
}

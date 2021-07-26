use std::io::ErrorKind;
use anyhow::Error;

pub fn EofErr(msg: &str) -> Error {
    Error::new(std::io::Error::new(ErrorKind::UnexpectedEof, msg))
}
use crate::{client::http::*, utils::ParserError};
use anyhow::{Error, Result};
use futures::StreamExt;
use quinn::*;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::{io::*, select};
use tracing::*;

pub async fn handle_quic_connection(
    mut streams: IncomingBiStreams,
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
) -> Result<()> {
    let (shutdown_tx, _) = broadcast::channel(1);

    loop {
        let stream = select! {
            s = streams.next() => {
                match s {
                    Some(stream) => stream,
                    None => {break;}
                }
            },
            _ = upper_shutdown.recv() => {
                // info
                break;
            }
        };

        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::Error::new(e));
            }
            Ok(s) => s,
        };
        let shutdown = shutdown_tx.subscribe();
        let pass_copy = password_hash.clone();
        tokio::spawn(handle_quic_outbound(stream, shutdown, pass_copy));
    }
    todo!()
}

async fn handle_quic_outbound(
    stream: (SendStream, RecvStream),
    mut upper_shutdown: broadcast::Receiver<()>,
    password_hash: Arc<String>,
) -> Result<()> {
    let (mut send, mut recv) = stream;
    let mut buffer = Vec::with_capacity(200);
    loop {
        let read = recv.read_buf(&mut buffer).await?;
        if read != 0 {
        } else {
            return Err(Error::new(ParserError::Invalid));
        }
    }
    todo!()
}

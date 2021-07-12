use crate::args::TrojanContext;
use anyhow::Result;
use tokio::{select, sync::oneshot};
use tracing::*;

pub async fn build_tunnel(ctrl_c: impl std::future::Future, context: TrojanContext) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    match context.options.server {
        #[cfg(feature = "server")]
        true => {
            use crate::server::run_server;
            info!("server-start");
            select! {
                _ = ctrl_c => {
                    info!("ctrl-c");
                }
                res = run_server(shutdown_rx, context) => {
                    match res {
                        Err(err) => {
                            error!("server quit due to {:?}", err);
                        }
                        ok => {
                            info!("server end: {:?}", ok);
                        }
                    }
                }
            }
        }
        #[cfg(feature = "client")]
        false => {
            use crate::client::run_client;
            info!("client-start");
            select! {
                _ = ctrl_c => {
                    info!("ctrl-c");
                }
                res = run_client(shutdown_rx, context) => {
                    match res {
                        Err(err) => {
                            error!("client quit due to {:?}", err);
                        }
                        ok => {
                            info!("client end: {:?}", ok);

                        }
                    }
                }
            }
        }
        #[allow(unreachable_patterns)]
        _ => panic!("function not complied"),
    }

    drop(shutdown_tx);
    Ok(())
}

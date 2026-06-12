use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::ProtocolVersion;
use crate::config::ClientConfig;
use crate::error::Result;
use crate::proxy::outbound::snell::SnellClientOutbound;
use crate::proxy::socks5::inbound::relay_socks5_connection;
use crate::server::shutdown::{SHUTDOWN_DRAIN_TIMEOUT, bind_tcp_listener, drain_connection_tasks};

pub async fn bind_configured_socks5_client_with_shutdown(
    config: ClientConfig,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = bind_tcp_listener(config.listen, false)?;
    serve_socks5_listener(
        listener,
        config.server,
        config.psk,
        config.reuse,
        config.version,
        config.quic_proxy,
        shutdown,
    )
    .await
}

async fn serve_socks5_listener(
    listener: TcpListener,
    server_addr: std::net::SocketAddr,
    psk: Zeroizing<Vec<u8>>,
    reuse: bool,
    version: ProtocolVersion,
    quic_proxy: bool,
    shutdown: CancellationToken,
) -> Result<()> {
    let outbound = Arc::new(SnellClientOutbound::new(
        server_addr,
        psk.to_vec(),
        reuse,
        version,
    )?);
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            result = listener.accept() => {
                let (local, peer_addr) = result?;
                let outbound = outbound.clone();
                tasks.spawn(async move {
                    let result = relay_socks5_connection(
                        local, outbound, quic_proxy,
                    ).await;
                    if let Err(err) = result {
                        tracing::debug!(%err, %peer_addr, "snell socks5 client connection failed");
                    }
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(err)) = result {
                    tracing::debug!(%err, "snell socks5 client task ended unexpectedly");
                }
            }
        }
    }
    drop(listener);

    drain_connection_tasks(tasks, SHUTDOWN_DRAIN_TIMEOUT).await;
    outbound.close_idle_connections().await;
    Ok(())
}

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::ProtocolVersion;
use crate::config::ClientConfig;
use crate::error::Result;
use crate::protocol::psk::SnellPsk;
use crate::proxy::outbound::RelayStats;
use crate::proxy::outbound::snell::SnellClientOutbound;
use crate::proxy::socks5::inbound::relay_socks5_connection;
use crate::server::shutdown::{SHUTDOWN_DRAIN_TIMEOUT, bind_tcp_listener, drain_connection_tasks};

/// Binds the configured SOCKS5 client listener and serves it until shutdown.
///
/// # Errors
///
/// Returns an error if the listener cannot bind, the configured Snell version
/// is unsupported, a relay connection fails, or listener shutdown fails.
pub async fn bind_configured_socks5_client_with_shutdown(
    config: ClientConfig,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = bind_tcp_listener(config.listen, false)?;
    let secret = SnellPsk::new(config.psk);
    serve_socks5_listener(
        listener,
        config.server,
        secret,
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
    secret: SnellPsk,
    reuse: bool,
    version: ProtocolVersion,
    quic_proxy: bool,
    shutdown: CancellationToken,
) -> Result<()> {
    let outbound = Arc::new(SnellClientOutbound::new(
        server_addr,
        secret,
        reuse,
        version,
    )?);
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            result = listener.accept() => {
                let (local, _peer_addr) = result?;
                let outbound = outbound.clone();
                tasks.spawn(relay_socks5_connection(local, outbound, quic_proxy));
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                log_socks5_client_task_result(result);
            }
        }
    }
    drop(listener);

    drain_connection_tasks(tasks, SHUTDOWN_DRAIN_TIMEOUT).await;
    outbound.close_idle_connections();
    Ok(())
}

fn log_socks5_client_task_result(
    result: Option<std::result::Result<Result<RelayStats>, tokio::task::JoinError>>,
) {
    match result {
        Some(Ok(Ok(_))) | None => {}
        Some(Ok(Err(err))) => {
            tracing::debug!(%err, "snell socks5 client connection failed");
        }
        Some(Err(err)) => {
            tracing::debug!(%err, "snell socks5 client task ended unexpectedly");
        }
    }
}

use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::config::{ServerConfig, TcpBrutalConfig};
use crate::error::{Error, Result};
use crate::net::dns::DnsResolver;
use crate::net::tcp_brutal::validate_tcp_brutal_available;
use crate::protocol::psk::SnellPsk;
use crate::protocol::v6::V6SaltReplayCache;
use crate::proxy::outbound::{RelayOptions, UpstreamRelay};
use crate::relay::quic_proxy::{QUIC_PROXY_FLOW_IDLE_TIMEOUT, serve_quic_proxy_socket};
use crate::server::shutdown::{SHUTDOWN_DRAIN_TIMEOUT, bind_tcp_listener};

mod listener;
pub(crate) mod shutdown;
#[cfg(test)]
mod tests;

pub(crate) use listener::{
    serve_tcp_listener_with_shutdown_and_timeout, serve_tcp_listeners_with_shutdown_and_timeout,
};

/// Binds the configured Snell TCP server and serves it until shutdown.
///
/// # Errors
///
/// Returns an error if DNS setup fails, TCP brutal is unavailable for the
/// requested configuration, a TCP or UDP socket cannot bind, or a listener task
/// exits with an error.
pub async fn bind_configured_tcp_server_with_shutdown(
    config: ServerConfig,
    shutdown: CancellationToken,
) -> Result<()> {
    let options = RelayOptions {
        ipv6: config.ipv6,
        dns_ip_preference: config.dns_ip_preference,
        upstream: UpstreamRelay::from(config.upstream_socks5),
        resolver: DnsResolver::from_config(config.dns)?,
    };
    let listeners = config
        .listen
        .iter()
        .copied()
        .map(|addr| bind_tcp_listener(addr, config.tcp_fast_open))
        .collect::<std::io::Result<Vec<_>>>()?;
    validate_tcp_brutal_available(config.tcp_brutal).await?;
    let secret = SnellPsk::new(config.psk);
    let quic_psk = secret.as_bytes().to_vec();
    let tcp_runtime = TcpServerRuntime {
        secret,
        options,
        tcp_brutal: config.tcp_brutal,
        v6_salt_replay_cache: V6SaltReplayCache::default(),
        shutdown: shutdown.clone(),
        drain_timeout: SHUTDOWN_DRAIN_TIMEOUT,
    };
    if !config.quic_proxy {
        return serve_tcp_listeners_with_shutdown_and_timeout(listeners, tcp_runtime).await;
    }

    let listen_addr = config.listen[0];
    let Some(listener) = listeners.into_iter().next() else {
        return Err(Error::Config(
            "snell-server.listen is required for quic_proxy".to_owned(),
        ));
    };
    let udp_socket = UdpSocket::bind(listen_addr).await?;
    let udp = serve_quic_proxy_socket(
        udp_socket,
        quic_psk,
        tcp_runtime.options.clone(),
        QUIC_PROXY_FLOW_IDLE_TIMEOUT,
        shutdown.clone(),
    );
    let tcp = serve_tcp_listener_with_shutdown_and_timeout(listener, tcp_runtime);
    tokio::pin!(udp);
    tokio::pin!(tcp);
    tokio::select! {
        result = &mut udp => {
            shutdown.cancel();
            let tcp_result = tcp.await;
            result?;
            tcp_result
        }
        result = &mut tcp => {
            shutdown.cancel();
            let udp_result = udp.await;
            result?;
            udp_result
        }
    }
}

#[derive(Clone)]
pub(crate) struct TcpServerRuntime {
    pub(in crate::server) secret: SnellPsk,
    pub(in crate::server) options: RelayOptions,
    pub(in crate::server) tcp_brutal: Option<TcpBrutalConfig>,
    pub(in crate::server) v6_salt_replay_cache: V6SaltReplayCache,
    pub(in crate::server) shutdown: CancellationToken,
    pub(in crate::server) drain_timeout: Duration,
}

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::sleep;

use crate::error::Result;
use crate::proxy::outbound::{PreparedUdpProxy, PreparedUdpRelay, RelayOptions};
use crate::session::activity::RelayActivity;
use crate::session::udp::stream::UdpServerStream;

use super::outbound::{
    relay_proxy_udp_to_snell, relay_snell_to_proxy_udp, relay_snell_to_udp, relay_udp_to_snell,
    wait_proxy_control_closed, write_zero_chunk,
};
use super::socket::{UdpSockets, bind_udp_socket, relay_bind_ip};

pub(crate) const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UdpRelayStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[cfg(test)]
async fn relay_udp_server_stream<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prepared = crate::proxy::outbound::open_udp(options.clone()).await?;
    let (activity, _last_activity) = RelayActivity::new();
    relay_udp_server_stream_prepared(stream, options, idle_timeout, prepared, &activity).await
}

pub(crate) async fn relay_udp_server_stream_prepared<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
    prepared: PreparedUdpRelay,
    activity: &RelayActivity,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match prepared {
        PreparedUdpRelay::Direct => {
            relay_udp_server_stream_direct(stream, options, idle_timeout, activity).await
        }
        PreparedUdpRelay::Proxy(proxy) => {
            relay_udp_server_stream_proxy(stream, options, idle_timeout, proxy, activity).await
        }
    }
}

async fn relay_udp_server_stream_direct<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
    activity: &RelayActivity,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = stream.into_parts();
    let sockets = UdpSockets::bind(options.ipv6).await?;
    let state = Arc::new(UdpAssociationState::new(activity.clone()));

    let end = {
        let snell_to_udp = relay_snell_to_udp(&mut reader, sockets.clone(), options, state.clone());
        let udp_to_snell = relay_udp_to_snell(&mut writer, sockets, state.clone());
        let idle = wait_udp_association_idle(state.clone(), idle_timeout);

        tokio::select! {
            result = snell_to_udp => {
                result?;
                UdpAssociationEnd::SnellClosed
            }
            result = udp_to_snell => {
                result?;
                UdpAssociationEnd::UdpToSnellClosed
            }
            () = idle => {
                tracing::debug!("snell udp stream idle timed out");
                UdpAssociationEnd::Idle
            }
        }
    };

    if matches!(end, UdpAssociationEnd::Idle) {
        // Client zero chunk already means client-side close. Server-originated
        // idle timeout sends zero chunk so the client can stop reading.
        write_zero_chunk(&mut writer).await?;
    }

    Ok(state.stats())
}

async fn relay_udp_server_stream_proxy<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
    proxy: PreparedUdpProxy,
    activity: &RelayActivity,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = stream.into_parts();
    let control = proxy.control;
    let relay_addr = proxy.relay_addr;
    let socket = Arc::new(bind_udp_socket(SocketAddr::new(relay_bind_ip(relay_addr), 0)).await?);
    let (mut control_reader, control_writer) = control.into_split();
    let state = Arc::new(UdpAssociationState::new(activity.clone()));

    let end = {
        let snell_to_proxy = relay_snell_to_proxy_udp(
            &mut reader,
            socket.clone(),
            relay_addr,
            options,
            state.clone(),
        );
        let proxy_to_snell =
            relay_proxy_udp_to_snell(&mut writer, socket, relay_addr, state.clone());
        let control_closed = wait_proxy_control_closed(&mut control_reader);
        let idle = wait_udp_association_idle(state.clone(), idle_timeout);

        tokio::select! {
            result = snell_to_proxy => {
                result?;
                UdpAssociationEnd::SnellClosed
            }
            result = proxy_to_snell => {
                result?;
                UdpAssociationEnd::UdpToSnellClosed
            }
            result = control_closed => {
                result?;
                UdpAssociationEnd::ProxyControlClosed
            }
            () = idle => {
                tracing::debug!("snell udp stream idle timed out");
                UdpAssociationEnd::Idle
            }
        }
    };
    drop(control_writer);

    if matches!(
        end,
        UdpAssociationEnd::Idle | UdpAssociationEnd::ProxyControlClosed
    ) {
        write_zero_chunk(&mut writer).await?;
    }

    Ok(state.stats())
}

// Polls the activity generation once per timeout window instead of waking on
// every datagram, so the effective idle cutoff lands in [timeout, 2*timeout).
async fn wait_udp_association_idle(state: Arc<UdpAssociationState>, timeout: Duration) {
    let mut observed = state.generation.load(Ordering::Relaxed);
    loop {
        sleep(timeout).await;
        let current = state.generation.load(Ordering::Relaxed);
        if current == observed {
            return;
        }
        observed = current;
    }
}

pub(super) struct UdpAssociationState {
    activity: RelayActivity,
    generation: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpAssociationEnd {
    SnellClosed,
    UdpToSnellClosed,
    ProxyControlClosed,
    Idle,
}

impl UdpAssociationState {
    const fn new(activity: RelayActivity) -> Self {
        Self {
            activity,
            generation: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    pub(super) fn add_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.mark_active();
    }

    pub(super) fn add_received(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.mark_active();
    }

    fn mark_active(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.activity.record();
    }

    fn stats(&self) -> UdpRelayStats {
        UdpRelayStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Result;
use crate::proxy::outbound::{PreparedUdpProxy, PreparedUdpRelay, RelayOptions};
use crate::session::activity::RelayActivity;
use crate::session::udp::stream::UdpServerStream;

use super::outbound::{
    relay_proxy_udp_to_snell, relay_snell_to_proxy_udp, relay_snell_to_udp, relay_udp_to_snell,
    wait_proxy_control_closed,
};
use super::socket::{UdpSockets, bind_udp_socket, relay_bind_ip};

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
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prepared = crate::proxy::outbound::open_udp(options.clone()).await?;
    let (activity, _last_activity) = RelayActivity::new();
    relay_udp_server_stream_prepared(stream, options, prepared, &activity).await
}

pub(crate) async fn relay_udp_server_stream_prepared<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    prepared: PreparedUdpRelay,
    activity: &RelayActivity,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match prepared {
        PreparedUdpRelay::Direct => relay_udp_server_stream_direct(stream, options, activity).await,
        PreparedUdpRelay::Proxy(proxy) => {
            relay_udp_server_stream_proxy(stream, options, proxy, activity).await
        }
    }
}

async fn relay_udp_server_stream_direct<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    activity: &RelayActivity,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = stream.into_parts();
    let sockets = UdpSockets::bind(options.ipv6).await?;
    let state = Arc::new(UdpAssociationState::new(activity.clone()));

    {
        let snell_to_udp = relay_snell_to_udp(&mut reader, sockets.clone(), options, state.clone());
        let udp_to_snell = relay_udp_to_snell(&mut writer, sockets, state.clone());

        tokio::select! {
            result = snell_to_udp => {
                result?;
            }
            result = udp_to_snell => {
                result?;
            }
        }
    };

    drop(writer);

    Ok(state.stats())
}

async fn relay_udp_server_stream_proxy<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
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

    {
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

        tokio::select! {
            result = snell_to_proxy => {
                result?;
            }
            result = proxy_to_snell => {
                result?;
            }
            result = control_closed => {
                result?;
            }
        }
    };
    drop(control_writer);

    drop(writer);

    Ok(state.stats())
}

pub(super) struct UdpAssociationState {
    activity: RelayActivity,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl UdpAssociationState {
    const fn new(activity: RelayActivity) -> Self {
        Self {
            activity,
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

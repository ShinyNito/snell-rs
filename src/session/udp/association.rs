use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{Instant, Sleep, sleep};

use crate::error::{Error, Result};
use crate::framed::SnellStreamWriter;
use crate::protocol::socks5::write_udp_packet as write_socks_udp_packet;
use crate::protocol::udp::parse_udp_request;
use crate::proxy::outbound::socks5::open_udp_associate_via_socks5;
use crate::proxy::outbound::udp::resolve_socks5_udp_relay_addr;
use crate::proxy::outbound::{
    PreparedUdpProxy, PreparedUdpRelay, RelayOptions, validate_proxy_udp_target,
};
use crate::session::activity::RelayActivity;
use crate::session::udp::io::{
    SnellUdpPacketKind, UdpRecvBatch, UdpSendPacket, max_socks_udp_datagram_len,
    parse_socks_udp_header, reframe_socks_udp_packet, send_udp_batch,
};
use crate::session::udp::stream::UdpServerStream;

use super::outbound::{relay_snell_to_udp, relay_udp_to_snell, wait_proxy_control_closed};
use super::socket::{UdpSockets, bind_udp_socket, relay_bind_ip};

#[cfg(not(test))]
const UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT: Duration = Duration::from_mins(1);
#[cfg(test)]
const UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT: Duration = Duration::from_millis(50);

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
    let state = Arc::new(UdpAssociationState::new(activity.clone()));
    let mut relay = Socks5UdpRelay::new(
        proxy.proxy_addr,
        options,
        writer.max_udp_application_payload_len(),
    );

    loop {
        if let Some(active) = relay.active_mut() {
            let event = {
                tokio::select! {
                    message = reader.read_udp_request_message() => ProxyRelayEvent::Snell(message),
                    ready = active.socket.readable() => ProxyRelayEvent::ProxyReadable(ready),
                    result = wait_proxy_control_closed(&mut active.control_reader) => {
                        ProxyRelayEvent::ControlClosed(result)
                    }
                    () = active.idle.as_mut() => ProxyRelayEvent::Idle,
                }
            };

            match event {
                ProxyRelayEvent::Snell(Ok(Some(message))) => {
                    relay.send_message(&message, &state).await?;
                }
                ProxyRelayEvent::Snell(Ok(None)) => break,
                ProxyRelayEvent::ProxyReadable(Ok(())) => {
                    if relay.write_responses(&mut writer, &state).await? {
                        break;
                    }
                }
                ProxyRelayEvent::ProxyReadable(Err(err)) => return Err(err.into()),
                ProxyRelayEvent::ControlClosed(Ok(())) => {
                    relay.close_active();
                }
                ProxyRelayEvent::ControlClosed(Err(err)) if err.is_closed_io() => {
                    relay.close_active();
                }
                ProxyRelayEvent::Snell(Err(err)) | ProxyRelayEvent::ControlClosed(Err(err)) => {
                    return Err(err);
                }
                ProxyRelayEvent::Idle => {
                    tracing::debug!("upstream socks5 udp associate idle timed out");
                    relay.close_active();
                }
            }
        } else {
            match reader.read_udp_request_message().await? {
                Some(message) => relay.send_message(&message, &state).await?,
                None => break,
            }
        }
    }

    drop(writer);

    Ok(state.stats())
}

struct Socks5UdpRelay {
    proxy_addr: SocketAddr,
    options: RelayOptions,
    active: Option<ActiveSocks5UdpRelay>,
    buffers: Box<Socks5UdpRelayBuffers>,
    max_snell_udp_payload_len: usize,
}

struct Socks5UdpRelayBuffers {
    proxy_header: BytesMut,
    recv_batch: UdpRecvBatch,
}

struct ActiveSocks5UdpRelay {
    control_reader: OwnedReadHalf,
    _control_writer: OwnedWriteHalf,
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    idle: Pin<Box<Sleep>>,
}

enum ProxyRelayEvent {
    Snell(Result<Option<Bytes>>),
    ProxyReadable(std::io::Result<()>),
    ControlClosed(Result<()>),
    Idle,
}

enum ProxyWriteBackStatus {
    Written(usize),
    Closed,
    Dropped,
    WouldBlock,
}

impl Socks5UdpRelay {
    fn new(
        proxy_addr: SocketAddr,
        options: RelayOptions,
        max_snell_udp_payload_len: usize,
    ) -> Self {
        Self {
            proxy_addr,
            options,
            active: None,
            buffers: Box::new(Socks5UdpRelayBuffers::new(max_snell_udp_payload_len)),
            max_snell_udp_payload_len,
        }
    }

    fn active_mut(&mut self) -> Option<&mut ActiveSocks5UdpRelay> {
        self.active.as_mut()
    }

    fn close_active(&mut self) {
        self.active = None;
    }

    async fn ensure_active(&mut self) -> Result<()> {
        if self.active.is_some() {
            return Ok(());
        }

        let association = open_udp_associate_via_socks5(self.proxy_addr).await?;
        let relay_addr = resolve_socks5_udp_relay_addr(
            self.proxy_addr,
            association.relay_endpoint,
            &self.options.resolver,
        )
        .await?;
        let socket =
            Arc::new(bind_udp_socket(SocketAddr::new(relay_bind_ip(relay_addr), 0)).await?);
        let (control_reader, control_writer) = association.control.into_split();
        self.active = Some(ActiveSocks5UdpRelay::new(
            control_reader,
            control_writer,
            socket,
            relay_addr,
        ));
        Ok(())
    }

    async fn send_message(
        &mut self,
        message: &[u8],
        state: &Arc<UdpAssociationState>,
    ) -> Result<()> {
        self.ensure_active().await?;
        let (socket, relay_addr) = {
            let active = self
                .active
                .as_ref()
                .expect("socks5 udp relay must be active after ensure_active");
            (active.socket.clone(), active.relay_addr)
        };
        let sent = self
            .buffers
            .write_request_to_proxy(
                message,
                &socket,
                relay_addr,
                &self.options,
                self.max_snell_udp_payload_len,
            )
            .await?;
        self.active
            .as_mut()
            .expect("socks5 udp relay must be active after writing request")
            .reset_idle();
        state.add_sent(sent as u64);
        Ok(())
    }

    async fn write_responses<W>(
        &mut self,
        writer: &mut SnellStreamWriter<W>,
        state: &Arc<UdpAssociationState>,
    ) -> Result<bool>
    where
        W: AsyncWrite + Unpin,
    {
        let Some(active) = self.active.as_ref() else {
            return Ok(false);
        };
        let socket = active.socket.clone();
        let relay_addr = active.relay_addr;
        match self
            .buffers
            .write_ready_responses(writer, &socket, relay_addr)
            .await?
        {
            ProxyWriteBackStatus::Written(n) => {
                if let Some(active) = self.active.as_mut() {
                    active.reset_idle();
                }
                state.add_received(n as u64);
                Ok(false)
            }
            ProxyWriteBackStatus::Closed => Ok(true),
            ProxyWriteBackStatus::Dropped | ProxyWriteBackStatus::WouldBlock => Ok(false),
        }
    }
}

impl Socks5UdpRelayBuffers {
    fn new(max_snell_udp_payload_len: usize) -> Self {
        Self {
            proxy_header: BytesMut::with_capacity(crate::session::udp::io::MAX_SOCKS_UDP_HEADER),
            recv_batch: UdpRecvBatch::new(max_socks_udp_datagram_len(max_snell_udp_payload_len)),
        }
    }

    async fn write_request_to_proxy(
        &mut self,
        message: &[u8],
        socket: &UdpSocket,
        relay_addr: SocketAddr,
        options: &RelayOptions,
        max_snell_udp_payload_len: usize,
    ) -> Result<usize> {
        let packet = parse_udp_request(message)?;
        let payload_len = packet.payload.len();
        validate_proxy_udp_target(packet, options.ipv6)?;
        self.proxy_header.clear();
        write_socks_udp_packet(&mut self.proxy_header, packet.address, packet.port, &[])?;
        send_udp_batch(
            socket,
            &[UdpSendPacket::parts(
                self.proxy_header.as_ref(),
                packet.payload,
                relay_addr,
            )],
            max_socks_udp_datagram_len(max_snell_udp_payload_len),
        )
        .await?;
        Ok(payload_len)
    }

    async fn write_ready_responses<W>(
        &mut self,
        writer: &mut SnellStreamWriter<W>,
        socket: &UdpSocket,
        relay_addr: SocketAddr,
    ) -> Result<ProxyWriteBackStatus>
    where
        W: AsyncWrite + Unpin,
    {
        let max_snell_udp_payload_len = writer.max_udp_application_payload_len();
        let count = match self.recv_batch.try_recv_from(socket) {
            Ok(count) => count,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(ProxyWriteBackStatus::WouldBlock);
            }
            Err(err) if err.is_closed_io() => return Ok(ProxyWriteBackStatus::Closed),
            Err(err) => return Err(err),
        };
        if count == 0 {
            return Ok(ProxyWriteBackStatus::WouldBlock);
        }

        let mut written = 0;
        let mut dropped = false;
        for index in 0..count {
            let Some(entry) = self.recv_batch.get(index) else {
                continue;
            };
            let peer = entry.peer();
            if entry.is_oversized() {
                tracing::debug!("dropped oversized proxy udp response");
                dropped = true;
                continue;
            }
            if peer != relay_addr {
                tracing::debug!(%peer, %relay_addr, "ignored udp packet from unexpected proxy peer");
                dropped = true;
                continue;
            }

            let header = match parse_socks_udp_header(entry.datagram()) {
                Ok(header) => header,
                Err(err) => {
                    tracing::debug!(%err, "ignored invalid proxy udp response");
                    dropped = true;
                    continue;
                }
            };
            let payload_len = header.payload_len();
            {
                let mut entry = self
                    .recv_batch
                    .get_mut(index)
                    .expect("checked UDP batch index must exist");
                let prefix_start = match reframe_socks_udp_packet(
                    entry.datagram_mut(),
                    &header,
                    SnellUdpPacketKind::Response,
                    max_snell_udp_payload_len,
                ) {
                    Ok(prefix_start) => prefix_start,
                    Err(Error::PayloadTooLarge) => {
                        tracing::debug!(payload_len, "dropped oversized proxy udp response");
                        dropped = true;
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                entry.datagram_mut().advance(prefix_start);
                if let Err(err) = writer
                    .write_payload_message_from_buffer(entry.datagram_mut())
                    .await
                {
                    if err.is_closed_io() {
                        return Ok(ProxyWriteBackStatus::Closed);
                    }
                    return Err(err);
                }
            }
            written += payload_len;
        }

        if written > 0 {
            Ok(ProxyWriteBackStatus::Written(written))
        } else if dropped {
            Ok(ProxyWriteBackStatus::Dropped)
        } else {
            Ok(ProxyWriteBackStatus::WouldBlock)
        }
    }
}

impl ActiveSocks5UdpRelay {
    fn new(
        control_reader: OwnedReadHalf,
        control_writer: OwnedWriteHalf,
        socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
    ) -> Self {
        Self {
            control_reader,
            _control_writer: control_writer,
            socket,
            relay_addr,
            idle: Box::pin(sleep(UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT)),
        }
    }

    fn reset_idle(&mut self) {
        self.idle
            .as_mut()
            .reset(Instant::now() + UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT);
    }
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

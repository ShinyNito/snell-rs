use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{Instant, Sleep, sleep, timeout};

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::net::dns::DnsResolver;
use crate::protocol::socks5::write_udp_packet as write_socks_udp_packet;
use crate::protocol::udp::{
    AddressRef, parse_udp_request, parse_udp_response, write_udp_response_prefix,
};
use crate::proxy::outbound::socks5::open_udp_associate_via_socks5;
use crate::proxy::outbound::udp::resolve_socks5_udp_relay_addr;
use crate::proxy::outbound::{
    PreparedUdpRelay, RelayOptions, RelayStats, validate_proxy_udp_target,
};
use crate::relay::activity::RelayActivity;
use crate::relay::udp::io::{
    SnellUdpPacketKind, UdpRecvBatch, UdpSendBatch, max_socks_udp_datagram_len,
    parse_socks_udp_header, reframe_socks_udp_packet,
};
use crate::transport::udp::stream::UdpServerStream;

use super::socket::{
    UDP_RESOLVE_TIMEOUT, UdpSockets, bind_udp_socket, relay_bind_ip, select_udp_target,
};

#[cfg(not(test))]
const UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT: Duration = Duration::from_mins(1);
#[cfg(test)]
const UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const CLIENT_SOCKS5_UDP_ASSOCIATION_TIMEOUT: Duration = Duration::from_mins(1);
#[cfg(test)]
const CLIENT_SOCKS5_UDP_ASSOCIATION_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UdpRelayStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl UdpRelayStats {
    pub(crate) const fn into_relay_stats(self) -> RelayStats {
        RelayStats {
            uploaded: self.bytes_sent,
            downloaded: self.bytes_received,
        }
    }
}

#[cfg(test)]
async fn run_udp_server_driver<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prepared = crate::proxy::outbound::open_udp(options.clone()).await?;
    let (activity, _last_activity) = RelayActivity::new();
    let driver = UdpRelayDriver::from_server_stream(stream, options, prepared, &activity).await?;
    tokio::pin!(driver);
    driver.await
}

pin_project! {
    pub(crate) struct UdpRelayDriver<R, W, C = tokio::io::Empty> {
        reader: SnellStreamReader<R>,
        writer: SnellStreamWriter<W>,
        #[pin]
        peer: UdpRelayPeer<C>,
        state: Arc<UdpAssociationState>,
        done: bool,
    }
}

pin_project! {
    #[project = UdpRelayPeerProj]
    enum UdpRelayPeer<C> {
        Direct {
            peer: DirectUdpPeer,
        },
        UpstreamSocks5 {
            #[pin]
            peer: Socks5UdpRelay,
        },
        Socks5Client {
            #[pin]
            peer: Socks5ClientUdpPeer<C>,
        },
    }
}

struct DirectUdpPeer {
    sockets: UdpSockets,
    options: RelayOptions,
    buffers: Box<DirectUdpBuffers>,
    resolve: Option<BoxUdpFuture<DirectResolvedSend>>,
    send: Option<PendingUdpSend>,
    writes: VecDeque<SnellWrite>,
}

struct DirectUdpBuffers {
    recv_v4: UdpRecvBatch,
    recv_v6: UdpRecvBatch,
}

pub(crate) type ClientPeerByUdpTarget = HashMap<OwnedUdpTarget, SocketAddr>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OwnedUdpTarget {
    address: OwnedUdpAddress,
    port: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum OwnedUdpAddress {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Default)]
pub(crate) struct Socks5ClientUdpSeed {
    pub(crate) client_addr: Option<SocketAddr>,
    pub(crate) client_peer_by_target: ClientPeerByUdpTarget,
    pub(crate) uploaded: u64,
}

pin_project! {
    struct Socks5ClientUdpPeer<C> {
        #[pin]
        control_reader: C,
        control_close: ControlCloseRead,
        udp_socket: Arc<UdpSocket>,
        control_peer_ip: IpAddr,
        route: Socks5ClientUdpRoute,
        udp_send: Option<PendingUdpSend>,
        snell_writes: VecDeque<SnellWrite>,
        #[pin]
        idle: Sleep,
        closing: bool,
    }
}

struct Socks5ClientUdpRoute {
    client_addr: Option<SocketAddr>,
    client_peer_by_target: ClientPeerByUdpTarget,
    buffers: Box<Socks5ClientUdpBuffers>,
    socks_udp_limit: usize,
}

struct Socks5ClientUdpBuffers {
    socks_header: BytesMut,
    socks_in_batch: UdpRecvBatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectWriteBackStatus {
    Written(usize),
    Closed,
    Dropped,
    WouldBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpResponseIpVersion {
    V4,
    V6,
}

type BoxUdpFuture<T> = Pin<Box<dyn Future<Output = Result<T>> + Send>>;

struct DirectResolvedSend {
    target: SocketAddr,
    payload: Bytes,
    credited: u64,
}

struct PendingUdpSend {
    socket: Arc<UdpSocket>,
    batch: UdpSendBatch,
    credited: u64,
}

struct SnellWrite {
    buffer: BytesMut,
    credited: u64,
}

struct ControlCloseRead {
    buffer: [u8; 128],
}

enum UdpDriverPoll {
    Pending,
    Progress,
    Done,
}

enum UpstreamActivePoll {
    Missing,
    Close,
    Recv {
        socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
    },
}

impl PendingUdpSend {
    fn new(socket: Arc<UdpSocket>, batch: UdpSendBatch, credited: u64) -> Self {
        Self {
            socket,
            batch,
            credited,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64>> {
        ready!(self.batch.poll_send(&self.socket, cx))?;
        Poll::Ready(Ok(self.credited))
    }
}

impl SnellWrite {
    fn new(buffer: BytesMut, credited: u64) -> Self {
        Self { buffer, credited }
    }

    fn poll<W>(
        &mut self,
        writer: &mut SnellStreamWriter<W>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<u64>>
    where
        W: AsyncWrite + Unpin,
    {
        ready!(writer.poll_write_payload_from_buffer(&mut self.buffer, cx))?;
        Poll::Ready(Ok(self.credited))
    }
}

impl ControlCloseRead {
    const fn new() -> Self {
        Self { buffer: [0; 128] }
    }

    fn poll<R>(&mut self, mut control: Pin<&mut R>, cx: &mut Context<'_>) -> Poll<Result<()>>
    where
        R: AsyncRead,
    {
        loop {
            let mut out = ReadBuf::new(&mut self.buffer);
            ready!(control.as_mut().poll_read(cx, &mut out))?;
            if out.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

fn poll_snell_writes<W>(
    writes: &mut VecDeque<SnellWrite>,
    snell_writer: &mut SnellStreamWriter<W>,
    cx: &mut Context<'_>,
) -> Poll<Result<Option<u64>>>
where
    W: AsyncWrite + Unpin,
{
    let Some(write) = writes.front_mut() else {
        return Poll::Ready(Ok(None));
    };
    let credited = ready!(write.poll(snell_writer, cx))?;
    writes.pop_front();
    Poll::Ready(Ok(Some(credited)))
}

fn payload_bytes_from_message(message: &Bytes, payload: &[u8]) -> Bytes {
    let start = payload.as_ptr() as usize - message.as_ptr() as usize;
    let end = start + payload.len();
    debug_assert!(end <= message.len());
    message.slice(start..end)
}

impl<R, W> UdpRelayDriver<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) async fn from_server_stream(
        stream: UdpServerStream<R, W>,
        options: RelayOptions,
        prepared: PreparedUdpRelay,
        activity: &RelayActivity,
    ) -> Result<Self> {
        let (reader, writer) = stream.into_parts();
        let max_snell_udp_payload_len = writer.max_udp_application_payload_len();
        let peer = match prepared {
            PreparedUdpRelay::Direct => UdpRelayPeer::Direct {
                peer: DirectUdpPeer::new(
                    UdpSockets::bind(options.ipv6).await?,
                    options,
                    max_snell_udp_payload_len,
                ),
            },
            PreparedUdpRelay::Proxy(proxy) => UdpRelayPeer::UpstreamSocks5 {
                peer: Socks5UdpRelay::new(proxy.proxy_addr, options, max_snell_udp_payload_len),
            },
        };
        Ok(Self {
            reader,
            writer,
            peer,
            state: Arc::new(UdpAssociationState::new(activity.clone())),
            done: false,
        })
    }
}

impl<R, W, C> UdpRelayDriver<R, W, C>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: AsyncRead,
{
    pub(crate) fn from_socks5_client_parts(
        reader: SnellStreamReader<R>,
        writer: SnellStreamWriter<W>,
        control_reader: C,
        udp_socket: Arc<UdpSocket>,
        control_peer_ip: IpAddr,
        seed: Socks5ClientUdpSeed,
        activity: &RelayActivity,
    ) -> Self {
        let state = Arc::new(UdpAssociationState::new(activity.clone()));
        if seed.uploaded > 0 {
            state.add_sent(seed.uploaded);
        }
        let socks_udp_limit = max_socks_udp_datagram_len(writer.max_udp_application_payload_len());
        Self {
            reader,
            writer,
            peer: UdpRelayPeer::Socks5Client {
                peer: Socks5ClientUdpPeer {
                    control_reader,
                    control_close: ControlCloseRead::new(),
                    udp_socket,
                    control_peer_ip,
                    route: Socks5ClientUdpRoute {
                        client_addr: seed.client_addr,
                        client_peer_by_target: seed.client_peer_by_target,
                        buffers: Box::new(Socks5ClientUdpBuffers {
                            socks_header: BytesMut::with_capacity(
                                crate::relay::udp::io::MAX_SOCKS_UDP_HEADER,
                            ),
                            socks_in_batch: UdpRecvBatch::new(socks_udp_limit),
                        }),
                        socks_udp_limit,
                    },
                    udp_send: None,
                    snell_writes: VecDeque::new(),
                    idle: sleep(CLIENT_SOCKS5_UDP_ASSOCIATION_TIMEOUT),
                    closing: false,
                },
            },
            state,
            done: false,
        }
    }
}

impl<R, W, C> Future for UdpRelayDriver<R, W, C>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: AsyncRead,
{
    type Output = Result<UdpRelayStats>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(Ok(this.state.stats()));
        }

        loop {
            let status = {
                let reader = &mut *this.reader;
                let writer = &mut *this.writer;
                let state = &*this.state;
                match this.peer.as_mut().project() {
                    UdpRelayPeerProj::Direct { peer } => {
                        poll_direct(reader, writer, peer, state, cx)
                    }
                    UdpRelayPeerProj::UpstreamSocks5 { peer } => {
                        poll_upstream_socks5(reader, writer, peer, state, cx)
                    }
                    UdpRelayPeerProj::Socks5Client { peer } => {
                        poll_socks5_client(reader, writer, peer, state, cx)
                    }
                }
            };

            match ready!(status)? {
                UdpDriverPoll::Pending => return Poll::Pending,
                UdpDriverPoll::Progress => {}
                UdpDriverPoll::Done => {
                    *this.done = true;
                    return Poll::Ready(Ok(this.state.stats()));
                }
            }
        }
    }
}

fn poll_direct<R, W>(
    reader: &mut SnellStreamReader<R>,
    writer: &mut SnellStreamWriter<W>,
    peer: &mut DirectUdpPeer,
    state: &Arc<UdpAssociationState>,
    cx: &mut Context<'_>,
) -> Poll<Result<UdpDriverPoll>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match ready!(poll_snell_writes(&mut peer.writes, writer, cx)) {
        Ok(Some(bytes)) => {
            state.add_received(bytes);
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
        Ok(None) => {}
        Err(err) if err.is_closed_io() => return Poll::Ready(Ok(UdpDriverPoll::Done)),
        Err(err) => return Poll::Ready(Err(err)),
    }

    if let Some(send) = &mut peer.send {
        let bytes = ready!(send.poll(cx))?;
        peer.send = None;
        state.add_sent(bytes);
        return Poll::Ready(Ok(UdpDriverPoll::Progress));
    }

    if let Some(resolve) = &mut peer.resolve {
        let resolved = ready!(resolve.as_mut().poll(cx))?;
        peer.resolve = None;
        let socket = peer.sockets.socket_for(resolved.target)?;
        peer.send = Some(PendingUdpSend::new(
            socket,
            UdpSendBatch::single(resolved.payload, resolved.target, crate::MAX_PACKET_SIZE),
            resolved.credited,
        ));
        return Poll::Ready(Ok(UdpDriverPoll::Progress));
    }

    match reader.poll_read_udp_request_message(cx) {
        Poll::Ready(Ok(Some(message))) => {
            peer.resolve = Some(resolve_direct_send(message, peer.options.clone()));
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
        Poll::Ready(Ok(None)) => return Poll::Ready(Ok(UdpDriverPoll::Done)),
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => {}
    }

    match peer.poll_recv_responses(writer, UdpResponseIpVersion::V4, cx)? {
        Poll::Ready(status) => match status {
            DirectWriteBackStatus::Closed => return Poll::Ready(Ok(UdpDriverPoll::Done)),
            DirectWriteBackStatus::Written(_)
            | DirectWriteBackStatus::Dropped
            | DirectWriteBackStatus::WouldBlock => {
                return Poll::Ready(Ok(UdpDriverPoll::Progress));
            }
        },
        Poll::Pending => {}
    }

    if peer.sockets.v6.is_some() {
        match peer.poll_recv_responses(writer, UdpResponseIpVersion::V6, cx)? {
            Poll::Ready(status) => match status {
                DirectWriteBackStatus::Closed => return Poll::Ready(Ok(UdpDriverPoll::Done)),
                DirectWriteBackStatus::Written(_)
                | DirectWriteBackStatus::Dropped
                | DirectWriteBackStatus::WouldBlock => {
                    return Poll::Ready(Ok(UdpDriverPoll::Progress));
                }
            },
            Poll::Pending => {}
        }
    }

    Poll::Ready(Ok(UdpDriverPoll::Pending))
}

#[allow(clippy::too_many_lines)]
fn poll_upstream_socks5<R, W>(
    reader: &mut SnellStreamReader<R>,
    writer: &mut SnellStreamWriter<W>,
    mut peer: Pin<&mut Socks5UdpRelay>,
    state: &Arc<UdpAssociationState>,
    cx: &mut Context<'_>,
) -> Poll<Result<UdpDriverPoll>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    {
        let mut this = peer.as_mut().project();
        match ready!(poll_snell_writes(this.writes, writer, cx)) {
            Ok(Some(bytes)) => {
                if let Some(active) = this.active.as_mut().as_pin_mut() {
                    reset_upstream_active_idle(active);
                }
                state.add_received(bytes);
                return Poll::Ready(Ok(UdpDriverPoll::Progress));
            }
            Ok(None) => {}
            Err(err) if err.is_closed_io() => return Poll::Ready(Ok(UdpDriverPoll::Done)),
            Err(err) => return Poll::Ready(Err(err)),
        }
    }

    {
        let mut this = peer.as_mut().project();
        if let Some(send) = this.send.as_mut() {
            let bytes = ready!(send.poll(cx))?;
            *this.send = None;
            if let Some(active) = this.active.as_mut().as_pin_mut() {
                reset_upstream_active_idle(active);
            }
            state.add_sent(bytes);
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
    }

    let opened = {
        let mut this = peer.as_mut().project();
        if let Some(opening) = this.opening.as_mut() {
            let active = ready!(opening.as_mut().poll(cx))?;
            this.active.as_mut().set(Some(active));
            *this.opening = None;
            true
        } else {
            false
        }
    };
    if opened {
        peer.as_mut().prepare_pending_message_send()?;
        return Poll::Ready(Ok(UdpDriverPoll::Progress));
    }

    {
        let mut this = peer.as_mut().project();
        let active_poll = match this.active.as_mut().as_pin_mut() {
            Some(active) => {
                let mut active = active.project();
                match active.control_close.poll(active.control_reader, cx) {
                    Poll::Ready(Ok(())) => UpstreamActivePoll::Close,
                    Poll::Ready(Err(err)) if err.is_closed_io() => UpstreamActivePoll::Close,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        if active.idle.as_mut().poll(cx).is_ready() {
                            tracing::debug!("upstream socks5 udp associate idle timed out");
                            UpstreamActivePoll::Close
                        } else {
                            UpstreamActivePoll::Recv {
                                socket: active.socket.clone(),
                                relay_addr: *active.relay_addr,
                            }
                        }
                    }
                }
            }
            None => UpstreamActivePoll::Missing,
        };

        match active_poll {
            UpstreamActivePoll::Close => {
                this.active.as_mut().set(None);
                return Poll::Ready(Ok(UdpDriverPoll::Progress));
            }
            UpstreamActivePoll::Recv { socket, relay_addr } => {
                match this.buffers.poll_recv_ready_responses(
                    this.writes,
                    writer,
                    &socket,
                    relay_addr,
                    cx,
                )? {
                    Poll::Ready(status) => match status {
                        ProxyWriteBackStatus::Closed => {
                            return Poll::Ready(Ok(UdpDriverPoll::Done));
                        }
                        ProxyWriteBackStatus::Written
                        | ProxyWriteBackStatus::Dropped
                        | ProxyWriteBackStatus::WouldBlock => {
                            return Poll::Ready(Ok(UdpDriverPoll::Progress));
                        }
                    },
                    Poll::Pending => {}
                }
            }
            UpstreamActivePoll::Missing => {}
        }
    }

    match reader.poll_read_udp_request_message(cx) {
        Poll::Ready(Ok(Some(message))) => {
            peer.as_mut().start_message_send(message)?;
            Poll::Ready(Ok(UdpDriverPoll::Progress))
        }
        Poll::Ready(Ok(None)) => Poll::Ready(Ok(UdpDriverPoll::Done)),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        Poll::Pending => Poll::Ready(Ok(UdpDriverPoll::Pending)),
    }
}

fn poll_socks5_client<R, W, C>(
    reader: &mut SnellStreamReader<R>,
    writer: &mut SnellStreamWriter<W>,
    peer: Pin<&mut Socks5ClientUdpPeer<C>>,
    state: &Arc<UdpAssociationState>,
    cx: &mut Context<'_>,
) -> Poll<Result<UdpDriverPoll>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: AsyncRead,
{
    let mut this = peer.project();

    if *this.closing {
        return poll_socks5_client_close(writer, cx);
    }

    match ready!(poll_snell_writes(this.snell_writes, writer, cx)) {
        Ok(Some(bytes)) => {
            state.add_sent(bytes);
            reset_sleep(this.idle.as_mut(), CLIENT_SOCKS5_UDP_ASSOCIATION_TIMEOUT);
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
        Ok(None) => {}
        Err(err) if err.is_closed_io() => return Poll::Ready(Ok(UdpDriverPoll::Done)),
        Err(err) => return Poll::Ready(Err(err)),
    }

    if let Some(send) = this.udp_send.as_mut() {
        let bytes = ready!(send.poll(cx))?;
        *this.udp_send = None;
        state.add_received(bytes);
        reset_sleep(this.idle.as_mut(), CLIENT_SOCKS5_UDP_ASSOCIATION_TIMEOUT);
        return Poll::Ready(Ok(UdpDriverPoll::Progress));
    }

    match this.control_close.poll(this.control_reader, cx) {
        Poll::Ready(Ok(())) => {
            *this.closing = true;
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => {}
    }

    if this.idle.as_mut().poll(cx).is_ready() {
        tracing::debug!("snell socks5 udp association idle timed out");
        *this.closing = true;
        return Poll::Ready(Ok(UdpDriverPoll::Progress));
    }

    match poll_client_socks_upload(
        this.route,
        this.snell_writes,
        this.udp_socket,
        *this.control_peer_ip,
        writer,
        cx,
    )? {
        Poll::Ready(Some(())) => return Poll::Ready(Ok(UdpDriverPoll::Progress)),
        Poll::Ready(None) | Poll::Pending => {}
    }

    match reader.poll_read_udp_response_message(cx) {
        Poll::Ready(Ok(Some(message))) => {
            prepare_client_snell_response(this.route, this.udp_send, this.udp_socket, &message)?;
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
        Poll::Ready(Ok(None)) => {
            *this.closing = true;
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
        Poll::Ready(Err(err)) if err.is_invalid_udp_packet() => {
            tracing::debug!(%err, "ignored invalid snell udp response");
            return Poll::Ready(Ok(UdpDriverPoll::Progress));
        }
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => {}
    }

    Poll::Ready(Ok(UdpDriverPoll::Pending))
}

fn poll_socks5_client_close<W>(
    writer: &mut SnellStreamWriter<W>,
    cx: &mut Context<'_>,
) -> Poll<Result<UdpDriverPoll>>
where
    W: AsyncWrite + Unpin,
{
    match ready!(writer.poll_write_zero_chunk(cx)) {
        Ok(()) => Poll::Ready(Ok(UdpDriverPoll::Done)),
        Err(err) if err.is_closed_io() => Poll::Ready(Ok(UdpDriverPoll::Done)),
        Err(err) => Poll::Ready(Err(err)),
    }
}

impl DirectUdpPeer {
    fn new(sockets: UdpSockets, options: RelayOptions, max_snell_udp_payload_len: usize) -> Self {
        Self {
            sockets,
            options,
            buffers: Box::new(DirectUdpBuffers::new(max_snell_udp_payload_len)),
            resolve: None,
            send: None,
            writes: VecDeque::new(),
        }
    }

    fn poll_recv_responses<W>(
        &mut self,
        writer: &mut SnellStreamWriter<W>,
        ip_version: UdpResponseIpVersion,
        cx: &mut Context<'_>,
    ) -> Result<Poll<DirectWriteBackStatus>>
    where
        W: AsyncWrite + Unpin,
    {
        let prefix_len = ip_version.prefix_len();
        let payload_limit = writer
            .max_udp_application_payload_len()
            .checked_sub(prefix_len)
            .ok_or(Error::PayloadTooLarge)?;
        let (socket, recv_batch) = match ip_version {
            UdpResponseIpVersion::V4 => (self.sockets.v4.as_ref(), &mut self.buffers.recv_v4),
            UdpResponseIpVersion::V6 => {
                let Some(socket) = self.sockets.v6.as_deref() else {
                    return Ok(Poll::Ready(DirectWriteBackStatus::WouldBlock));
                };
                (socket, &mut self.buffers.recv_v6)
            }
        };

        let count =
            match recv_batch.poll_recv_from_with_headroom(socket, prefix_len, payload_limit, cx) {
                Poll::Ready(Ok(count)) => count,
                Poll::Ready(Err(err)) if err.is_closed_io() => {
                    return Ok(Poll::Ready(DirectWriteBackStatus::Closed));
                }
                Poll::Ready(Err(err)) => return Err(err),
                Poll::Pending => return Ok(Poll::Pending),
            };
        Ok(Poll::Ready(queue_direct_udp_responses(
            &mut self.writes,
            recv_batch,
            ip_version,
            count,
        )?))
    }
}

impl DirectUdpBuffers {
    fn new(max_udp_application_payload_len: usize) -> Self {
        Self {
            recv_v4: UdpRecvBatch::new(max_udp_application_payload_len),
            recv_v6: UdpRecvBatch::new(max_udp_application_payload_len),
        }
    }
}

impl OwnedUdpTarget {
    pub(crate) fn from_ref(address: AddressRef<'_>, port: u16) -> Self {
        Self {
            address: OwnedUdpAddress::from_ref(address),
            port,
        }
    }

    pub(crate) fn update(&mut self, address: AddressRef<'_>, port: u16) {
        self.address.update(address);
        self.port = port;
    }

    pub(crate) fn address_ref(&self) -> AddressRef<'_> {
        self.address.as_ref()
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn quic_init_host<'a>(&'a self, scratch: &'a mut String) -> &'a str {
        quic_init_host(self.address_ref(), scratch)
    }
}

impl OwnedUdpAddress {
    fn from_ref(address: AddressRef<'_>) -> Self {
        match address {
            AddressRef::Domain(host) => Self::Domain(host.to_owned()),
            AddressRef::Ip(ip) => Self::Ip(ip),
        }
    }

    fn update(&mut self, address: AddressRef<'_>) {
        match (self, address) {
            (Self::Domain(current), AddressRef::Domain(host)) => {
                if current != host {
                    current.clear();
                    current.push_str(host);
                }
            }
            (Self::Ip(current), AddressRef::Ip(ip)) => *current = ip,
            (slot, AddressRef::Domain(host)) => *slot = Self::Domain(host.to_owned()),
            (slot, AddressRef::Ip(ip)) => *slot = Self::Ip(ip),
        }
    }

    fn as_ref(&self) -> AddressRef<'_> {
        match self {
            Self::Domain(host) => AddressRef::Domain(host),
            Self::Ip(ip) => AddressRef::Ip(*ip),
        }
    }
}

pub(crate) fn quic_init_host<'a>(address: AddressRef<'a>, scratch: &'a mut String) -> &'a str {
    match address {
        AddressRef::Domain(host) => host,
        AddressRef::Ip(ip) => {
            scratch.clear();
            write!(scratch, "{ip}").expect("writing IpAddr to String cannot fail");
            scratch
        }
    }
}

pub(crate) fn is_allowed_socks_udp_peer(control_peer_ip: IpAddr, udp_peer: SocketAddr) -> bool {
    udp_peer.ip() == control_peer_ip
}

fn reset_sleep(mut sleep: Pin<&mut Sleep>, timeout: Duration) {
    sleep.as_mut().reset(Instant::now() + timeout);
}

fn reset_upstream_active_idle(active: Pin<&mut ActiveSocks5UdpRelay>) {
    let active = active.project();
    reset_sleep(active.idle, UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT);
}

fn poll_client_socks_upload<W>(
    route: &mut Socks5ClientUdpRoute,
    snell_writes: &mut VecDeque<SnellWrite>,
    udp_socket: &UdpSocket,
    control_peer_ip: IpAddr,
    writer: &mut SnellStreamWriter<W>,
    cx: &mut Context<'_>,
) -> Result<Poll<Option<()>>>
where
    W: AsyncWrite + Unpin,
{
    let max_snell_udp_payload_len = writer.max_udp_application_payload_len();
    let count = match route.buffers.socks_in_batch.poll_recv_from(udp_socket, cx) {
        Poll::Ready(Ok(count)) => count,
        Poll::Ready(Err(err)) => return Err(err),
        Poll::Pending => return Ok(Poll::Pending),
    };
    let mut wrote = false;

    for index in 0..count {
        let Some(entry) = route.buffers.socks_in_batch.get(index) else {
            continue;
        };
        let peer = entry.peer();
        if entry.is_oversized() || entry.datagram().len() > route.socks_udp_limit {
            tracing::debug!("ignored oversized socks5 udp datagram");
            continue;
        }
        if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
            tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
            continue;
        }

        let header = match parse_socks_udp_header(entry.datagram()) {
            Ok(header) => header,
            Err(err) => {
                tracing::debug!(%err, "ignored invalid socks5 udp datagram");
                continue;
            }
        };
        let payload_len = header.payload_len();
        let (target_address, target_port) = header.target(entry.datagram())?;
        let target = OwnedUdpTarget::from_ref(target_address, target_port);
        {
            let mut entry = route
                .buffers
                .socks_in_batch
                .get_mut(index)
                .expect("checked UDP batch index must exist");
            let prefix_start = match reframe_socks_udp_packet(
                entry.datagram_mut(),
                &header,
                SnellUdpPacketKind::Request,
                max_snell_udp_payload_len,
            ) {
                Ok(prefix_start) => prefix_start,
                Err(Error::PayloadTooLarge) => {
                    tracing::debug!("ignored oversized socks5 udp datagram");
                    continue;
                }
                Err(err) => return Err(err),
            };
            entry.datagram_mut().advance(prefix_start);
            let frame = entry.datagram_mut().split();
            snell_writes.push_back(SnellWrite::new(frame, payload_len as u64));
        }
        route.client_peer_by_target.insert(target, peer);
        route.client_addr = Some(peer);
        wrote = true;
    }

    Ok(Poll::Ready(wrote.then_some(())))
}

fn prepare_client_snell_response(
    route: &mut Socks5ClientUdpRoute,
    udp_send: &mut Option<PendingUdpSend>,
    udp_socket: &Arc<UdpSocket>,
    message: &Bytes,
) -> Result<bool> {
    let packet = match parse_udp_response(message) {
        Ok(packet) => packet,
        Err(err) if err.is_invalid_udp_packet() => {
            tracing::debug!(%err, "ignored invalid snell udp response");
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    let Some(peer) = client_peer_for_response(
        &route.client_peer_by_target,
        route.client_addr,
        packet.address,
        packet.port,
    ) else {
        return Ok(false);
    };

    route.buffers.socks_header.clear();
    write_socks_udp_packet(
        &mut route.buffers.socks_header,
        packet.address,
        packet.port,
        &[],
    )?;
    let header = route.buffers.socks_header.split().freeze();
    let payload = payload_bytes_from_message(message, packet.payload);
    *udp_send = Some(PendingUdpSend::new(
        udp_socket.clone(),
        UdpSendBatch::parts(header, payload, peer, route.socks_udp_limit),
        packet.payload.len() as u64,
    ));
    Ok(true)
}

fn client_peer_for_response(
    client_peer_by_target: &ClientPeerByUdpTarget,
    last_client_peer: Option<SocketAddr>,
    address: AddressRef<'_>,
    port: u16,
) -> Option<SocketAddr> {
    client_peer_by_target
        .get(&OwnedUdpTarget::from_ref(address, port))
        .copied()
        .or(last_client_peer)
}

fn resolve_direct_send(message: Bytes, options: RelayOptions) -> BoxUdpFuture<DirectResolvedSend> {
    Box::pin(async move {
        let (address, port, payload) = {
            let packet = parse_udp_request(&message)?;
            (
                packet.address.map_domain(str::to_owned),
                packet.port,
                payload_bytes_from_message(&message, packet.payload),
            )
        };
        let credited = payload.len() as u64;
        let target = match address {
            OwnedAddressRef::Ip(ip) => {
                if !options.ipv6 && ip.is_ipv6() {
                    return Err(Error::Ipv6Disabled);
                }
                SocketAddr::new(ip, port)
            }
            OwnedAddressRef::Domain(host) => {
                let addrs = timeout(
                    UDP_RESOLVE_TIMEOUT,
                    options.resolver.lookup_socket_addrs(host.as_str(), port),
                )
                .await
                .map_err(|_| Error::DnsTimeout)??;
                select_udp_target(&addrs, options.ipv6, options.dns_ip_preference)?
            }
        };
        Ok(DirectResolvedSend {
            target,
            payload,
            credited,
        })
    })
}

enum OwnedAddressRef {
    Domain(String),
    Ip(IpAddr),
}

trait AddressRefExt {
    fn map_domain(self, map: impl FnOnce(&str) -> String) -> OwnedAddressRef;
}

impl AddressRefExt for AddressRef<'_> {
    fn map_domain(self, map: impl FnOnce(&str) -> String) -> OwnedAddressRef {
        match self {
            AddressRef::Domain(host) => OwnedAddressRef::Domain(map(host)),
            AddressRef::Ip(ip) => OwnedAddressRef::Ip(ip),
        }
    }
}

fn queue_direct_udp_responses(
    writes: &mut VecDeque<SnellWrite>,
    recv_batch: &mut UdpRecvBatch,
    ip_version: UdpResponseIpVersion,
    count: usize,
) -> Result<DirectWriteBackStatus> {
    if count == 0 {
        return Ok(DirectWriteBackStatus::WouldBlock);
    }

    let prefix_len = ip_version.prefix_len();
    let mut written = 0;
    let mut dropped = false;
    for index in 0..count {
        let Some(entry) = recv_batch.get(index) else {
            continue;
        };
        let peer = entry.peer();
        let payload_len = entry.payload_len();
        if entry.is_oversized() {
            tracing::debug!("dropped oversized udp response");
            dropped = true;
            continue;
        }
        if !ip_version.matches(peer.ip()) {
            tracing::debug!(%peer, "ignored udp response from unexpected address family");
            dropped = true;
            continue;
        }

        {
            let mut entry = recv_batch
                .get_mut(index)
                .expect("checked UDP batch index must exist");
            let mut prefix = &mut entry.datagram_mut()[..prefix_len];
            write_udp_response_prefix(&mut prefix, AddressRef::Ip(peer.ip()), peer.port())?;
            debug_assert!(prefix.is_empty());
            let frame = entry.datagram_mut().split();
            writes.push_back(SnellWrite::new(frame, payload_len as u64));
        }
        written += payload_len;
    }

    if written > 0 {
        Ok(DirectWriteBackStatus::Written(written))
    } else if dropped {
        Ok(DirectWriteBackStatus::Dropped)
    } else {
        Ok(DirectWriteBackStatus::WouldBlock)
    }
}

impl UdpResponseIpVersion {
    const fn prefix_len(self) -> usize {
        match self {
            Self::V4 => 1 + 4 + 2,
            Self::V6 => 1 + 16 + 2,
        }
    }

    const fn matches(self, ip: std::net::IpAddr) -> bool {
        matches!(
            (self, ip),
            (Self::V4, std::net::IpAddr::V4(_)) | (Self::V6, std::net::IpAddr::V6(_))
        )
    }
}

pin_project! {
    #[project = Socks5UdpRelayProj]
    struct Socks5UdpRelay {
        proxy_addr: SocketAddr,
        options: RelayOptions,
        #[pin]
        active: Option<ActiveSocks5UdpRelay>,
        opening: Option<BoxUdpFuture<ActiveSocks5UdpRelay>>,
        pending_message: Option<Bytes>,
        send: Option<PendingUdpSend>,
        writes: VecDeque<SnellWrite>,
        buffers: Box<Socks5UdpRelayBuffers>,
        max_snell_udp_payload_len: usize,
    }
}

struct Socks5UdpRelayBuffers {
    proxy_header: BytesMut,
    recv_batch: UdpRecvBatch,
}

pin_project! {
    struct ActiveSocks5UdpRelay {
        #[pin]
        control_reader: OwnedReadHalf,
        control_close: ControlCloseRead,
        _control_writer: OwnedWriteHalf,
        socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        #[pin]
        idle: Sleep,
    }
}

enum ProxyWriteBackStatus {
    Written,
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
            opening: None,
            pending_message: None,
            send: None,
            writes: VecDeque::new(),
            buffers: Box::new(Socks5UdpRelayBuffers::new(max_snell_udp_payload_len)),
            max_snell_udp_payload_len,
        }
    }

    fn start_message_send(self: Pin<&mut Self>, message: Bytes) -> Result<()> {
        let this = self.project();
        if this.active.as_ref().get_ref().is_none() {
            *this.pending_message = Some(message);
            start_socks5_udp_opening(
                this.opening,
                *this.proxy_addr,
                this.options.resolver.clone(),
            );
            return Ok(());
        }

        *this.pending_message = Some(message);
        prepare_socks5_pending_message_send(this)
    }

    fn prepare_pending_message_send(self: Pin<&mut Self>) -> Result<()> {
        let this = self.project();
        prepare_socks5_pending_message_send(this)
    }
}

fn start_socks5_udp_opening(
    opening: &mut Option<BoxUdpFuture<ActiveSocks5UdpRelay>>,
    proxy_addr: SocketAddr,
    resolver: DnsResolver,
) {
    if opening.is_some() {
        return;
    }

    *opening = Some(Box::pin(async move {
        let association = open_udp_associate_via_socks5(proxy_addr).await?;
        let relay_addr =
            resolve_socks5_udp_relay_addr(proxy_addr, association.relay_endpoint, &resolver)
                .await?;
        let socket =
            Arc::new(bind_udp_socket(SocketAddr::new(relay_bind_ip(relay_addr), 0)).await?);
        let (control_reader, control_writer) = association.control.into_split();
        Ok(ActiveSocks5UdpRelay::new(
            control_reader,
            control_writer,
            socket,
            relay_addr,
        ))
    }));
}

fn prepare_socks5_pending_message_send(this: Socks5UdpRelayProj<'_>) -> Result<()> {
    let Socks5UdpRelayProj {
        proxy_addr,
        options,
        mut active,
        opening,
        pending_message,
        send,
        buffers,
        max_snell_udp_payload_len,
        ..
    } = this;
    let Some(message) = pending_message.take() else {
        return Ok(());
    };
    let Some(active) = active.as_mut().as_pin_mut() else {
        *pending_message = Some(message);
        start_socks5_udp_opening(opening, *proxy_addr, options.resolver.clone());
        return Ok(());
    };
    let active = active.project();
    *send = Some(buffers.prepare_request_to_proxy(
        &message,
        active.socket.clone(),
        *active.relay_addr,
        options,
        *max_snell_udp_payload_len,
    )?);
    Ok(())
}

impl Socks5UdpRelayBuffers {
    fn new(max_snell_udp_payload_len: usize) -> Self {
        Self {
            proxy_header: BytesMut::with_capacity(crate::relay::udp::io::MAX_SOCKS_UDP_HEADER),
            recv_batch: UdpRecvBatch::new(max_socks_udp_datagram_len(max_snell_udp_payload_len)),
        }
    }

    fn prepare_request_to_proxy(
        &mut self,
        message: &Bytes,
        socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        options: &RelayOptions,
        max_snell_udp_payload_len: usize,
    ) -> Result<PendingUdpSend> {
        let packet = parse_udp_request(message)?;
        let payload_len = packet.payload.len();
        validate_proxy_udp_target(packet, options.ipv6)?;
        let payload = payload_bytes_from_message(message, packet.payload);
        self.proxy_header.clear();
        write_socks_udp_packet(&mut self.proxy_header, packet.address, packet.port, &[])?;
        let header = self.proxy_header.split().freeze();
        Ok(PendingUdpSend::new(
            socket,
            UdpSendBatch::parts(
                header,
                payload,
                relay_addr,
                max_socks_udp_datagram_len(max_snell_udp_payload_len),
            ),
            payload_len as u64,
        ))
    }

    fn poll_recv_ready_responses<W>(
        &mut self,
        writes: &mut VecDeque<SnellWrite>,
        snell_writer: &mut SnellStreamWriter<W>,
        socket: &UdpSocket,
        relay_addr: SocketAddr,
        cx: &mut Context<'_>,
    ) -> Result<Poll<ProxyWriteBackStatus>>
    where
        W: AsyncWrite + Unpin,
    {
        let max_snell_udp_payload_len = snell_writer.max_udp_application_payload_len();
        let count = match self.recv_batch.poll_recv_from(socket, cx) {
            Poll::Ready(Ok(count)) => count,
            Poll::Ready(Err(err)) if err.is_closed_io() => {
                return Ok(Poll::Ready(ProxyWriteBackStatus::Closed));
            }
            Poll::Ready(Err(err)) => return Err(err),
            Poll::Pending => return Ok(Poll::Pending),
        };
        if count == 0 {
            return Ok(Poll::Ready(ProxyWriteBackStatus::WouldBlock));
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
                let frame = entry.datagram_mut().split();
                writes.push_back(SnellWrite::new(frame, payload_len as u64));
            }
            written += payload_len;
        }

        if written > 0 {
            Ok(Poll::Ready(ProxyWriteBackStatus::Written))
        } else if dropped {
            Ok(Poll::Ready(ProxyWriteBackStatus::Dropped))
        } else {
            Ok(Poll::Ready(ProxyWriteBackStatus::WouldBlock))
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
            control_close: ControlCloseRead::new(),
            _control_writer: control_writer,
            socket,
            relay_addr,
            idle: sleep(UPSTREAM_SOCKS5_UDP_ASSOCIATE_IDLE_TIMEOUT),
        }
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

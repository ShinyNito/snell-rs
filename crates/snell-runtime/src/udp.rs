//! SOCKS5 UDP ASSOCIATE dispatcher and Snell UDP sessions.
//!
//! One dispatcher task owns `peer → association`. Lookup is `HashMap::get`.
//! Each association owns one Snell TCP. Idle uses a per-association `Sleep`,
//! not an O(N) map scan. Queue full is `try_send` failure plus a real counter.

use crate::buffer::PooledBuffer;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use snell_protocol::socks5::{self, Reply};
use snell_protocol::{
    Address, Error, MAX_UDP_PACKET_ADDR_LEN, UDP_ASSOCIATION_IDLE_SECS, UDP_DATAGRAM_MAX,
    decode_udp_request, decode_udp_response,
};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Instant;

use crate::client::dial;
use crate::codec::{TcpDecoder, TcpEncoder, with_codec};
use crate::dns::DnsResolver;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::packet::{PacketBuf, PacketQuota};
use crate::platform::prepare_session_stream;
use crate::pool::Connection;
use crate::session::{
    RecordEvent, decode_once, read_server_tunnel, with_handshake_timeout, write_reject,
    write_tunnel, write_udp_request, write_udp_response, write_udp_setup,
};
use crate::socks::write_socks5_reply_bind;
use crate::{ClientConfig, ServerConfig};

const UDP_ASSOCIATION_MAX: usize = 256;
const UDP_CONTROL_MAX: usize = 256;
const UDP_QUEUE_MAX: usize = 16;
const UDP_POOL_MAX_BUFS: usize = 64;
const UDP_POOL_MAX_BYTES: usize = 4 * 1024 * 1024;
const UDP_DNS_CACHE_MAX: usize = 1024;
const UDP_DNS_CACHE_TTL_SECS: u64 = 30;

#[derive(Clone, Copy, Debug)]
pub struct UdpLimits {
    pub max_associations: usize,
    pub max_controls: usize,
    pub queue_max: usize,
    pub pool_bufs: usize,
    pub pool_bytes: usize,
    pub idle: Duration,
    pub dns_max: usize,
    pub dns_ttl: Duration,
}

impl Default for UdpLimits {
    fn default() -> Self {
        Self {
            max_associations: UDP_ASSOCIATION_MAX,
            max_controls: UDP_CONTROL_MAX,
            queue_max: UDP_QUEUE_MAX,
            pool_bufs: UDP_POOL_MAX_BUFS,
            pool_bytes: UDP_POOL_MAX_BYTES,
            idle: Duration::from_secs(UDP_ASSOCIATION_IDLE_SECS),
            dns_max: UDP_DNS_CACHE_MAX,
            dns_ttl: Duration::from_secs(UDP_DNS_CACHE_TTL_SECS),
        }
    }
}

/// Relaxed counters; `Debug` prints their current values.
#[derive(Debug, Default)]
pub struct UdpMetrics {
    pub queue_full: AtomicU64,
    pub no_buffer: AtomicU64,
    pub frag_dropped: AtomicU64,
    pub oversize: AtomicU64,
    pub map_full: AtomicU64,
    pub invalid: AtomicU64,
    pub idle_expired: AtomicU64,
    pub associations: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct UdpOptions {
    pub limits: UdpLimits,
    pub metrics: Arc<UdpMetrics>,
    pub dns: DnsResolver,
}

impl Default for UdpOptions {
    fn default() -> Self {
        Self::new().expect("system DNS configuration")
    }
}

impl UdpOptions {
    pub fn new() -> Result<Self, SessionError> {
        let limits = UdpLimits::default();
        Ok(Self {
            dns: DnsResolver::try_from_system(limits.dns_max, limits.dns_ttl)?,
            metrics: Arc::new(UdpMetrics::default()),
            limits,
        })
    }
}

type ControlId = u64;

enum Ctrl {
    Add(ControlId),
    Remove(ControlId),
    Closed(SocketAddr),
}

struct InboundDgram {
    dest: Address,
    header_len: usize,
    buf: PacketBuf,
}

/// SOCKS5 UDP relay state shared by the dispatcher and association tasks.
struct Relay {
    socket: UdpSocket,
    config: Arc<ClientConfig>,
    kdf: Arc<KdfLimiter>,
    quota: Arc<PacketQuota>,
    ctrl: mpsc::Sender<Ctrl>,
}

/// A client peer's association task and the control connection it belongs to.
struct Association {
    tx: mpsc::Sender<InboundDgram>,
    control: ControlId,
}

/// Associations by client peer, and the peers of each SOCKS5 control
/// connection. The two maps change together.
#[derive(Default)]
struct Routes {
    associations: HashMap<SocketAddr, Association>,
    peers: HashMap<ControlId, HashSet<SocketAddr>>,
}

#[derive(Clone)]
pub(crate) struct UdpHub {
    bind: SocketAddr,
    ctrl: mpsc::Sender<Ctrl>,
    next_control: Arc<AtomicU64>,
    /// One permit per live control connection, up to `max_controls`.
    controls: Arc<Semaphore>,
    _dispatcher: Arc<StopDispatcher>,
}

struct StopDispatcher(tokio::task::AbortHandle);
impl Drop for StopDispatcher {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sends the reserved `Remove` for a control, then frees its slot.
struct ControlGuard {
    close: Option<mpsc::OwnedPermit<Ctrl>>,
    id: ControlId,
    _slot: OwnedSemaphorePermit,
}
impl Drop for ControlGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.close.take() {
            permit.send(Ctrl::Remove(self.id));
        }
    }
}

impl UdpHub {
    pub async fn start(
        listen: SocketAddr,
        config: Arc<ClientConfig>,
        kdf: Arc<KdfLimiter>,
    ) -> Result<Self, SessionError> {
        let socket = UdpSocket::bind(SocketAddr::new(listen.ip(), 0)).await?;
        let bind = socket.local_addr()?;
        let limits = config.udp.limits;
        let quota = Arc::new(PacketQuota::new(
            Arc::clone(&config.buffers),
            limits.pool_bufs,
            limits.pool_bytes,
        ));
        let ctrl_cap = limits
            .max_controls
            .saturating_mul(2)
            .saturating_add(limits.max_associations)
            .max(1);
        let (ctrl, ctrl_rx) = mpsc::channel(ctrl_cap);
        let relay = Relay {
            socket,
            config,
            kdf,
            quota,
            ctrl: ctrl.clone(),
        };
        let dispatcher = tokio::spawn(dispatcher(Arc::new(relay), ctrl_rx));
        Ok(Self {
            bind,
            ctrl,
            next_control: Arc::new(AtomicU64::new(1)),
            controls: Arc::new(Semaphore::new(limits.max_controls)),
            _dispatcher: Arc::new(StopDispatcher(dispatcher.abort_handle())),
        })
    }

    pub async fn handle_associate(&self, mut local: TcpStream) -> Result<(), SessionError> {
        let Ok(slot) = Arc::clone(&self.controls).try_acquire_owned() else {
            write_socks5_reply_bind(&mut local, Reply::GeneralFailure, self.bind).await?;
            return Err(SessionError::UdpLimit);
        };
        let id = self.next_control.fetch_add(1, Ordering::Relaxed);
        // Reserve the close notification before registering the control. Drop
        // can then notify cancellation without spawning or losing a full-queue send.
        let close = self
            .ctrl
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| SessionError::Cancelled)?;
        let _guard = ControlGuard {
            close: Some(close),
            id,
            _slot: slot,
        };
        self.ctrl
            .send(Ctrl::Add(id))
            .await
            .map_err(|_| SessionError::Cancelled)?;
        write_socks5_reply_bind(&mut local, Reply::Succeeded, self.bind).await?;
        // The association lives until the SOCKS5 control connection closes.
        while local.read(&mut [0u8; 1]).await.is_ok_and(|n| n > 0) {}
        Ok(())
    }
}

fn offer(
    tx: &mpsc::Sender<InboundDgram>,
    dgram: InboundDgram,
    metrics: &UdpMetrics,
) -> Result<(), PacketBuf> {
    match tx.try_send(dgram) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(dgram)) => {
            metrics.queue_full.fetch_add(1, Ordering::Relaxed);
            Err(dgram.buf)
        }
        Err(mpsc::error::TrySendError::Closed(dgram)) => {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            Err(dgram.buf)
        }
    }
}

async fn dispatcher(relay: Arc<Relay>, mut ctrl_rx: mpsc::Receiver<Ctrl>) {
    let metrics = &relay.config.udp.metrics;
    let mut routes = Routes::default();
    loop {
        tokio::select! {
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { return; };
                routes.apply(ctrl, metrics);
                continue;
            }
            ready = relay.socket.readable() => { if ready.is_err() { return; } }
        }
        tokio::select! {
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { return; };
                routes.apply(ctrl, metrics);
            }
            result = relay.quota.recv_from(&relay.socket) => match result {
                Ok(Some((buf, peer))) => routes.route(&relay, peer, buf),
                Ok(None) => {
                    metrics.no_buffer.fetch_add(1, Ordering::Relaxed);
                    tokio::select! {
                        ctrl = ctrl_rx.recv() => {
                            let Some(ctrl) = ctrl else { return; };
                            routes.apply(ctrl, metrics);
                        }
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                    }
                }
                Err(_) => {}
            },
        }
    }
}

impl Routes {
    fn apply(&mut self, ctrl: Ctrl, metrics: &UdpMetrics) {
        match ctrl {
            Ctrl::Add(id) => {
                self.peers.insert(id, HashSet::new());
            }
            Ctrl::Remove(id) => {
                for peer in self.peers.remove(&id).unwrap_or_default() {
                    if self.associations.remove(&peer).is_some() {
                        metrics.associations.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
            Ctrl::Closed(peer) => {
                if let Some(association) = self.associations.remove(&peer) {
                    metrics.associations.fetch_sub(1, Ordering::Relaxed);
                    if let Some(peers) = self.peers.get_mut(&association.control) {
                        peers.remove(&peer);
                    }
                }
            }
        }
    }

    /// Prefer a control with no peers yet; `None` when no control is live.
    fn pick_control(&self) -> Option<ControlId> {
        self.peers
            .iter()
            .find(|(_, peers)| peers.is_empty())
            .or_else(|| self.peers.iter().next())
            .map(|(id, _)| *id)
    }

    /// Queue a client datagram on its association, starting one for a new peer.
    fn route(&mut self, relay: &Arc<Relay>, peer: SocketAddr, buf: PacketBuf) {
        let udp = &relay.config.udp;
        let metrics = &udp.metrics;
        let packet = match socks5::parse_udp_packet(buf.as_slice()) {
            Ok(packet) => packet,
            Err(_) => {
                metrics.invalid.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        if packet.frag != 0 {
            metrics.frag_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let dgram = InboundDgram {
            dest: packet.destination.into_owned(),
            header_len: packet.header_len,
            buf,
        };

        if let Some(association) = self.associations.get(&peer) {
            let _ = offer(&association.tx, dgram, metrics);
            return;
        }
        let Some(control) = self.pick_control() else {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if self.associations.len() >= udp.limits.max_associations {
            metrics.map_full.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let (tx, rx) = mpsc::channel(udp.limits.queue_max.max(1));
        if offer(&tx, dgram, metrics).is_err() {
            return;
        }
        self.associations.insert(peer, Association { tx, control });
        if let Some(peers) = self.peers.get_mut(&control) {
            peers.insert(peer);
        }
        metrics.associations.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(client = %peer, "udp association created");
        tokio::spawn(run_association(Arc::clone(relay), rx, peer));
    }
}

enum AssocEnd {
    Idle,
    Closed,
}

async fn run_association(
    relay: Arc<Relay>,
    mut rx: mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
) {
    if let Ok(AssocEnd::Idle) = relay.associate(&mut rx, peer).await {
        relay
            .config
            .udp
            .metrics
            .idle_expired
            .fetch_add(1, Ordering::Relaxed);
        tracing::debug!(client = %peer, "udp association expired after idle timeout");
    }
    // Datagrams still queued when the association dies (dial failure, TCP
    // error, idle race) must return to the pool, or its live count leaks.
    drop(rx);
    let _ = relay.ctrl.send(Ctrl::Closed(peer)).await;
}

impl Relay {
    /// Open a Snell UDP session for `peer` and relay until idle or closed.
    async fn associate(
        &self,
        rx: &mut mpsc::Receiver<InboundDgram>,
        peer: SocketAddr,
    ) -> Result<AssocEnd, SessionError> {
        let mut conn = dial(&self.config, &self.kdf).await?;
        let Connection { stream, codec } = &mut conn;
        prepare_session_stream(stream)?;
        let mut recv = self.config.buffers.get(snell_protocol::V6_WIRE_CAP);
        with_codec!(codec, |encoder, decoder| {
            with_handshake_timeout(async {
                write_udp_setup(encoder, &self.config.buffers, stream).await?;
                let leftover =
                    read_server_tunnel(decoder, &mut recv, stream, &self.kdf, &self.config.psk)
                        .await?;
                if !leftover.is_empty() {
                    return Err(Error::Malformed("udp tunnel leftover").into());
                }
                Ok(())
            })
            .await?;
            self.pump(stream, encoder, decoder, &mut recv, rx, peer)
                .await
        })
    }

    async fn pump<E: TcpEncoder, D: TcpDecoder>(
        &self,
        snell: &mut TcpStream,
        encoder: &mut E,
        decoder: &mut D,
        recv: &mut PooledBuffer,
        rx: &mut mpsc::Receiver<InboundDgram>,
        peer: SocketAddr,
    ) -> Result<AssocEnd, SessionError> {
        let (buffers, udp) = (&self.config.buffers, &self.config.udp);
        let (mut snell_r, mut snell_w) = snell.split();
        let sleep = tokio::time::sleep(udp.limits.idle);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => return Ok(AssocEnd::Idle),
                dgram = rx.recv() => {
                    let Some(dgram) = dgram else {
                        return Ok(AssocEnd::Closed);
                    };
                    sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                    let payload = &dgram.buf.as_slice()[dgram.header_len..];
                    let address = dgram.dest.as_view();
                    match write_udp_request(encoder, buffers, &mut snell_w, address, payload).await {
                        Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                            udp.metrics.oversize.fetch_add(1, Ordering::Relaxed);
                        }
                        result => result?,
                    }
                }
                record = decode_once(decoder, recv, &mut snell_r, &self.kdf, &self.config.psk) => {
                    sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                    let RecordEvent::Data(record) = record? else {
                        return Ok(AssocEnd::Closed);
                    };
                    let plain = record.plaintext(recv.filled());
                    send_socks_response(&self.socket, peer, plain, &udp.metrics).await?;
                    decoder.consume(recv, &record)?;
                }
            }
        }
    }
}

async fn send_socks_response(
    socks_udp: &UdpSocket,
    peer: SocketAddr,
    plain: &[u8],
    metrics: &UdpMetrics,
) -> Result<(), SessionError> {
    let pkt = match decode_udp_response(plain) {
        Ok(pkt) => pkt,
        Err(_) => {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    // Keep the payload borrowed from the decoded record until the atomic send.
    let mut hdr = [0u8; 3 + MAX_UDP_PACKET_ADDR_LEN];
    let hdr_len = match socks5::encode_udp_header(&mut hdr, 0, pkt.address) {
        Ok(n) => n,
        Err(_) => {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    let needed = hdr_len.saturating_add(pkt.payload.len());
    if needed > UDP_DATAGRAM_MAX {
        metrics.oversize.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    crate::platform::send_udp_parts(socks_udp, peer, &hdr[..hdr_len], pkt.payload).await?;
    Ok(())
}

struct AssocGuard<'a>(&'a UdpMetrics);

impl Drop for AssocGuard<'_> {
    fn drop(&mut self) {
        self.0.associations.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Relay one Snell UDP association through the server's outbound.
pub(crate) async fn run_server_udp<E: TcpEncoder, D: TcpDecoder>(
    mut snell: TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    config: &ServerConfig,
    kdf: &KdfLimiter,
    mut recv: PooledBuffer,
) -> Result<(), SessionError> {
    let (buffers, udp) = (&config.buffers, &config.udp);
    let max = udp.limits.max_associations as u64;
    let admitted = udp
        .metrics
        .associations
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < max).then_some(n + 1)
        });
    if admitted.is_err() {
        udp.metrics.map_full.fetch_add(1, Ordering::Relaxed);
        let _ = write_reject(encoder, buffers, &mut snell, "udp association limit").await;
        return Err(SessionError::UdpLimit);
    }
    let _guard = AssocGuard(&udp.metrics);

    let mut flow = match config.outbound.open_udp(&udp.dns, buffers).await {
        Ok(flow) => flow,
        Err(error) => {
            let _ = write_reject(encoder, buffers, &mut snell, &error.to_string()).await;
            return Err(error);
        }
    };
    write_tunnel(encoder, buffers, &mut snell).await?;

    let (mut snell_r, mut snell_w) = snell.split();
    let sleep = tokio::time::sleep(udp.limits.idle);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => {
                udp.metrics.idle_expired.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("udp association expired after idle timeout");
                return Ok(());
            }
            record = decode_once(decoder, &mut recv, &mut snell_r, kdf, &config.psk) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                let RecordEvent::Data(record) = record? else {
                    return Ok(());
                };
                let sent = match decode_udp_request(record.plaintext(recv.filled())) {
                    Ok(packet) => flow.send(packet.address, packet.payload, &udp.dns).await,
                    Err(error) => Err(error.into()),
                };
                if sent.is_err() {
                    udp.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                }
                decoder.consume(&mut recv, &record)?;
            }
            reply = flow.recv(&udp.metrics.frag_dropped, &udp.metrics.invalid) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                let reply = reply?;
                let address = reply.addr.as_view();
                match write_udp_response(encoder, buffers, &mut snell_w, address, reply.payload())
                    .await
                {
                    Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                        udp.metrics.oversize.fetch_add(1, Ordering::Relaxed);
                    }
                    result => result?,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snell_protocol::{AddressRef, ProtocolFlavor, Psk};
    use std::net::Ipv4Addr;

    /// A relay that dials `server`, and the receiver of its control messages.
    async fn test_relay(
        server: SocketAddr,
        quota: Arc<PacketQuota>,
    ) -> (Arc<Relay>, mpsc::Receiver<Ctrl>) {
        let (ctrl, ctrl_rx) = mpsc::channel(4);
        let config = ClientConfig {
            listen: server,
            server,
            psk: Psk::new(b"0123456789abcdef").unwrap(),
            version: ProtocolFlavor::V4,
            pool: None,
            udp: UdpOptions::default(),
            buffers: Arc::clone(&quota.buffers),
        };
        let relay = Relay {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            config: Arc::new(config),
            kdf: Arc::new(KdfLimiter::new()),
            quota,
            ctrl,
        };
        (Arc::new(relay), ctrl_rx)
    }

    #[tokio::test]
    async fn existing_association_routes_packets_and_releases_rejected_queue_items() {
        let quota = Arc::new(PacketQuota::new(Arc::default(), 2, 1024));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 3456));
        let (relay, _ctrl_rx) = test_relay(peer, Arc::clone(&quota)).await;
        let (tx, mut rx) = mpsc::channel(1);
        let mut routes = Routes::default();
        routes
            .associations
            .insert(peer, Association { tx, control: 7 });
        let mut packet = [0u8; 64];
        let header = socks5::encode_udp_header(&mut packet, 0, AddressRef::Ip(peer)).unwrap();
        packet[header..header + 4].copy_from_slice(b"ping");
        for _ in 0..2 {
            let mut buf = quota.acquire(header + 4).unwrap();
            buf.extend(&packet[..header + 4]).unwrap();
            routes.route(&relay, peer, buf);
        }
        assert_eq!(routes.associations.len(), 1);
        let metrics = &relay.config.udp.metrics;
        assert_eq!(metrics.queue_full.load(Ordering::Relaxed), 1);
        assert_eq!(quota.live(), 1);
        let packet = rx.try_recv().unwrap();
        assert_eq!(&packet.buf.as_slice()[packet.header_len..], b"ping");
        drop(packet);
        assert_eq!(quota.live(), 0);
        assert_eq!(quota.buffers.leased_bytes(), 0);
    }

    #[tokio::test]
    async fn association_dial_failure_releases_queued_buffers() {
        let quota = Arc::new(PacketQuota::new(Arc::default(), 4, 1024 * 1024));
        let (tx, rx) = mpsc::channel(4);
        for _ in 0..2 {
            let mut buf = quota.acquire(64).unwrap();
            buf.extend(b"ping").unwrap();
            tx.try_send(InboundDgram {
                dest: Address::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
                header_len: 0,
                buf,
            })
            .unwrap();
        }
        assert_eq!(quota.live(), 2);
        // Bind then drop: dialing this port fails fast with connection refused.
        let dead = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let (relay, mut ctrl_rx) = test_relay(dead, Arc::clone(&quota)).await;
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 3456));
        run_association(relay, rx, peer).await;
        assert!(matches!(ctrl_rx.recv().await, Some(Ctrl::Closed(_))));
        assert_eq!(
            quota.live(),
            0,
            "queued datagram buffers must return to the pool when the association dies"
        );
    }

    #[tokio::test]
    async fn socks_responses_are_single_datagrams() {
        let metrics = UdpMetrics::default();
        let payload: Vec<u8> = (0..1400).map(|n| n as u8).collect();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpSocket::bind(bind).await.unwrap();
            let receiver = UdpSocket::bind(bind).await.unwrap();
            for source in ["203.0.113.5:1234", "[2001:db8::5]:1234"] {
                let source = AddressRef::Ip(source.parse().unwrap());
                for payload in [b"".as_slice(), payload.as_slice()] {
                    let mut plain = vec![0; 1500];
                    let n =
                        snell_protocol::encode_udp_response(&mut plain, source, payload).unwrap();
                    send_socks_response(
                        &sender,
                        receiver.local_addr().unwrap(),
                        &plain[..n],
                        &metrics,
                    )
                    .await
                    .unwrap();
                    let mut received = [0; 1500];
                    let (n, peer) = tokio::time::timeout(
                        Duration::from_secs(1),
                        receiver.recv_from(&mut received),
                    )
                    .await
                    .expect("response must arrive as one datagram")
                    .unwrap();
                    assert_eq!(peer, sender.local_addr().unwrap());
                    let packet = socks5::parse_udp_packet(&received[..n]).unwrap();
                    assert_eq!(packet.frag, 0);
                    assert_eq!(packet.destination, source);
                    assert_eq!(&received[packet.header_len..n], payload);
                    assert_eq!(
                        receiver.try_recv_from(&mut received).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock,
                        "header and payload must be sent in one datagram",
                    );
                }
            }
        }
        assert_eq!(metrics.no_buffer.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn socks_response_propagates_socket_error() {
        let metrics = UdpMetrics::default();
        let mut plain = [0; 64];
        let n = snell_protocol::encode_udp_response(
            &mut plain,
            AddressRef::Ip("127.0.0.1:9".parse().unwrap()),
            b"pong",
        )
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            send_socks_response(&socket, "[::1]:9".parse().unwrap(), &plain[..n], &metrics),
        )
        .await
        .expect("socket errors must not enter the readiness retry loop")
        .unwrap_err();
        assert!(matches!(error, SessionError::Io(_)));
    }

    #[tokio::test]
    async fn oversized_socks_response_does_not_send_a_header_datagram() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut plain = vec![0; UDP_DATAGRAM_MAX];
        // A Snell payload fits the runtime limit but exceeds IPv4's UDP limit
        // once the SOCKS5 header is included. The OS must reject the whole send.
        let payload = vec![0x5a; 65507];
        let n = snell_protocol::encode_udp_response(
            &mut plain,
            AddressRef::Ip("203.0.113.5:1234".parse().unwrap()),
            &payload,
        )
        .unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            send_socks_response(
                &sender,
                receiver.local_addr().unwrap(),
                &plain[..n],
                &UdpMetrics::default(),
            ),
        )
        .await
        .expect("an oversized datagram must not be retried")
        .unwrap_err();
        assert!(matches!(error, SessionError::Io(_)));
        assert_eq!(
            receiver.try_recv_from(&mut [0; 64]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
        );
    }

    #[test]
    fn queue_full_is_observable_and_not_success() {
        let (tx, _rx) = mpsc::channel(1);
        let metrics = UdpMetrics::default();
        let dummy = || InboundDgram {
            dest: Address::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
            header_len: 0,
            buf: Arc::new(PacketQuota::new(Arc::default(), 1, 64))
                .acquire(3)
                .unwrap(),
        };
        assert!(offer(&tx, dummy(), &metrics).is_ok());
        let second = offer(&tx, dummy(), &metrics);
        assert!(second.is_err(), "queue full must not report success");
        assert_eq!(metrics.queue_full.load(Ordering::Relaxed), 1);
    }
    #[tokio::test]
    async fn cancelled_associate_removes_control_once() {
        let (ctrl, mut rx) = mpsc::channel(2);
        let controls = Arc::new(Semaphore::new(1));
        let dispatcher = tokio::spawn(std::future::pending::<()>());
        let hub = UdpHub {
            bind: "127.0.0.1:1234".parse().unwrap(),
            _dispatcher: Arc::new(StopDispatcher(dispatcher.abort_handle())),
            ctrl,
            next_control: Arc::new(AtomicU64::new(1)),
            controls: Arc::clone(&controls),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (local, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move { hub.handle_associate(local).await });
        let mut reply = [0; 10];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        assert!(matches!(rx.recv().await, Some(Ctrl::Add(1))));
        assert_eq!(controls.available_permits(), 0);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(matches!(rx.recv().await, Some(Ctrl::Remove(1))));
        assert_eq!(controls.available_permits(), 1);
        assert!(rx.try_recv().is_err(), "one removal only");
    }

    #[tokio::test]
    async fn control_drop_delivers_reserved_close_and_releases_count() {
        let (tx, mut rx) = mpsc::channel(2);
        let controls = Arc::new(Semaphore::new(1));
        let guard = ControlGuard {
            close: Some(tx.clone().reserve_owned().await.unwrap()),
            id: 7,
            _slot: Arc::clone(&controls).try_acquire_owned().unwrap(),
        };
        tx.send(Ctrl::Add(7)).await.unwrap();
        drop(guard);
        assert_eq!(controls.available_permits(), 1);
        assert!(matches!(rx.recv().await, Some(Ctrl::Add(7))));
        assert!(matches!(rx.recv().await, Some(Ctrl::Remove(7))));
    }
}

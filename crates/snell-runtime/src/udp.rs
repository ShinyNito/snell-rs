//! SOCKS5 UDP ASSOCIATE dispatcher and Snell UDP sessions.
//!
//! One dispatcher task owns `peer → association`. Lookup is `HashMap::get`.
//! Each association owns one Snell TCP. Idle uses a per-association `Sleep`,
//! not an O(N) map scan. Queue full is `try_send` failure plus a real counter.

use crate::buffer::{BufferPool, PooledBuffer};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use snell_protocol::socks5::{self, Reply};
use snell_protocol::{
    Address, Error, MAX_UDP_PACKET_ADDR_LEN, ProtocolFlavor, Psk, UDP_ASSOCIATION_IDLE_SECS,
    UDP_DATAGRAM_MAX, decode_udp_request, decode_udp_response,
};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::client::dial_and_codec;
use crate::codec::{TcpDecoder, TcpEncoder, with_codec};
use crate::dns::DnsResolver;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::packet::{PacketBuf, PacketQuota};
use crate::session::{
    RecordEvent, decode_once, read_server_tunnel, with_handshake_timeout, write_reject,
    write_tunnel, write_udp_request, write_udp_response, write_udp_setup,
};
use crate::socks::write_socks5_reply_bind;

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

#[derive(Default)]
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

impl fmt::Debug for UdpMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpMetrics")
            .field("queue_full", &self.queue_full.load(Ordering::Relaxed))
            .field("no_buffer", &self.no_buffer.load(Ordering::Relaxed))
            .field("frag_dropped", &self.frag_dropped.load(Ordering::Relaxed))
            .field("oversize", &self.oversize.load(Ordering::Relaxed))
            .field("map_full", &self.map_full.load(Ordering::Relaxed))
            .field("invalid", &self.invalid.load(Ordering::Relaxed))
            .field("idle_expired", &self.idle_expired.load(Ordering::Relaxed))
            .field("associations", &self.associations.load(Ordering::Relaxed))
            .finish()
    }
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

struct AssocEntry {
    tx: mpsc::Sender<InboundDgram>,
    control: ControlId,
}

struct Control {
    peers: HashSet<SocketAddr>,
}

#[derive(Clone)]
struct Dial {
    server: SocketAddr,
    psk: Psk,
    version: ProtocolFlavor,
    kdf: Arc<KdfLimiter>,
}

#[derive(Clone)]
pub(crate) struct UdpHub {
    bind: SocketAddr,
    ctrl: mpsc::Sender<Ctrl>,
    next_control: Arc<AtomicU64>,
    control_count: Arc<AtomicU64>,
    limits: UdpLimits,
    _dispatcher: Arc<StopDispatcher>,
}

struct StopDispatcher(tokio::task::AbortHandle);
impl Drop for StopDispatcher {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ControlGuard {
    count: Arc<AtomicU64>,
    close: Option<mpsc::OwnedPermit<Ctrl>>,
    id: ControlId,
}
impl Drop for ControlGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.close.take() {
            permit.send(Ctrl::Remove(self.id));
        }
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl UdpHub {
    pub async fn start(
        listen: SocketAddr,
        config: crate::ClientConfig,
        kdf: Arc<KdfLimiter>,
    ) -> Result<Self, SessionError> {
        let socket = UdpSocket::bind(SocketAddr::new(listen.ip(), 0)).await?;
        let bind = socket.local_addr()?;
        let socket = Arc::new(socket);
        let limits = config.udp.limits;
        let metrics = config.udp.metrics.clone();
        let pool = Arc::new(PacketQuota::new(
            config.buffers.clone(),
            limits.pool_bufs,
            limits.pool_bytes,
        ));
        let ctrl_cap = limits
            .max_controls
            .saturating_mul(2)
            .saturating_add(limits.max_associations)
            .max(1);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(ctrl_cap);
        let dial = Dial {
            server: config.server,
            psk: config.psk.clone(),
            version: config.version,
            kdf,
        };
        let dispatcher = tokio::spawn(dispatcher(
            socket,
            ctrl_rx,
            ctrl_tx.clone(),
            pool,
            metrics.clone(),
            limits,
            dial,
        ));
        Ok(Self {
            bind,
            _dispatcher: Arc::new(StopDispatcher(dispatcher.abort_handle())),
            ctrl: ctrl_tx,
            next_control: Arc::new(AtomicU64::new(1)),
            control_count: Arc::new(AtomicU64::new(0)),
            limits,
        })
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind
    }

    pub async fn handle_associate(&self, mut local: TcpStream) -> Result<(), SessionError> {
        let prev = self.control_count.fetch_add(1, Ordering::Relaxed);
        if prev >= self.limits.max_controls as u64 {
            self.control_count.fetch_sub(1, Ordering::Relaxed);
            write_socks5_reply_bind(&mut local, Reply::GeneralFailure, self.bind_addr()).await?;
            return Err(SessionError::UdpLimit);
        }
        let id = self.next_control.fetch_add(1, Ordering::Relaxed);
        let mut guard = ControlGuard {
            count: self.control_count.clone(),
            close: None,
            id,
        };
        // Reserve the close notification before registering the control. Drop
        // can then notify cancellation without spawning or losing a full-queue send.
        guard.close = Some(
            self.ctrl
                .clone()
                .reserve_owned()
                .await
                .map_err(|_| SessionError::Cancelled)?,
        );
        self.ctrl
            .send(Ctrl::Add(id))
            .await
            .map_err(|_| SessionError::Cancelled)?;
        write_socks5_reply_bind(&mut local, Reply::Succeeded, self.bind_addr()).await?;
        let mut buf = [0u8; 1];
        loop {
            match local.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        Ok(())
    }
}

fn pick_control(controls: &HashMap<ControlId, Control>) -> Option<ControlId> {
    controls
        .iter()
        .find(|(_, control)| control.peers.is_empty())
        .map(|(id, _)| *id)
        .or_else(|| controls.keys().copied().next())
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

async fn dispatcher(
    socket: Arc<UdpSocket>,
    mut ctrl_rx: mpsc::Receiver<Ctrl>,
    ctrl_tx: mpsc::Sender<Ctrl>,
    pool: Arc<PacketQuota>,
    metrics: Arc<UdpMetrics>,
    limits: UdpLimits,
    dial: Dial,
) {
    let mut map: HashMap<SocketAddr, AssocEntry> = HashMap::new();
    let mut controls: HashMap<ControlId, Control> = HashMap::new();
    loop {
        tokio::select! {
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { return; };
                apply_ctrl(ctrl, &mut map, &mut controls, &metrics);
                continue;
            }
            ready = socket.readable() => { if ready.is_err() { return; } }
        }
        tokio::select! {
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { return; };
                apply_ctrl(ctrl, &mut map, &mut controls, &metrics);
            }
            result = pool.recv_from(&socket) => {
                match result {
                    Ok(Some((buf, peer))) => handle_datagram(peer, buf, &mut map, &mut controls, &pool, &metrics, limits, &dial, &socket, &ctrl_tx),
                    Ok(None) => {
                        metrics.no_buffer.fetch_add(1, Ordering::Relaxed);
                        tokio::select! {
                            ctrl = ctrl_rx.recv() => {
                                let Some(ctrl) = ctrl else { return; };
                                apply_ctrl(ctrl, &mut map, &mut controls, &metrics);
                            }
                            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

fn apply_ctrl(
    ctrl: Ctrl,
    map: &mut HashMap<SocketAddr, AssocEntry>,
    controls: &mut HashMap<ControlId, Control>,
    metrics: &UdpMetrics,
) {
    match ctrl {
        Ctrl::Add(id) => {
            controls.insert(
                id,
                Control {
                    peers: HashSet::new(),
                },
            );
        }
        Ctrl::Remove(id) => {
            if let Some(control) = controls.remove(&id) {
                for peer in control.peers {
                    if map.remove(&peer).is_some() {
                        metrics.associations.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        }
        Ctrl::Closed(peer) => {
            if let Some(entry) = map.remove(&peer) {
                metrics.associations.fetch_sub(1, Ordering::Relaxed);
                if let Some(control) = controls.get_mut(&entry.control) {
                    control.peers.remove(&peer);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_datagram(
    peer: SocketAddr,
    buf: PacketBuf,
    map: &mut HashMap<SocketAddr, AssocEntry>,
    controls: &mut HashMap<ControlId, Control>,
    pool: &Arc<PacketQuota>,
    metrics: &Arc<UdpMetrics>,
    limits: UdpLimits,
    dial: &Dial,
    socket: &Arc<UdpSocket>,
    ctrl_tx: &mpsc::Sender<Ctrl>,
) {
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
    let dest = packet.destination.into_owned();
    let header_len = packet.header_len;
    let dgram = InboundDgram {
        dest,
        header_len,
        buf,
    };

    if let Some(entry) = map.get(&peer) {
        let _ = offer(&entry.tx, dgram, metrics);
        return;
    }

    if controls.is_empty() {
        metrics.invalid.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if map.len() >= limits.max_associations {
        metrics.map_full.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(control) = pick_control(controls) else {
        return;
    };
    let (tx, rx) = mpsc::channel(limits.queue_max.max(1));
    if offer(&tx, dgram, metrics).is_err() {
        return;
    }
    map.insert(peer, AssocEntry { tx, control });
    if let Some(slot) = controls.get_mut(&control) {
        slot.peers.insert(peer);
    }
    metrics.associations.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(client = %peer, "udp association created");
    tokio::spawn(client_assoc(
        rx,
        peer,
        socket.clone(),
        dial.clone(),
        ctrl_tx.clone(),
        metrics.clone(),
        limits.idle,
        pool.clone(),
    ));
}

enum AssocEnd {
    Idle,
    Closed,
}

#[allow(clippy::too_many_arguments)]
async fn client_assoc(
    mut rx: mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
    socks_udp: Arc<UdpSocket>,
    dial: Dial,
    ctrl: mpsc::Sender<Ctrl>,
    metrics: Arc<UdpMetrics>,
    idle: Duration,
    pool: Arc<PacketQuota>,
) {
    let end = client_assoc_inner(&mut rx, peer, socks_udp, dial, &metrics, idle, &pool).await;
    if matches!(end, Ok(AssocEnd::Idle)) {
        metrics.idle_expired.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(client = %peer, "udp association expired after idle timeout");
    }
    // Datagrams still queued when the association dies (dial failure, TCP
    // error, idle race) must return to the pool, or its live count leaks.
    drop(rx);
    let _ = ctrl.send(Ctrl::Closed(peer)).await;
}

#[allow(clippy::too_many_arguments)]
async fn client_assoc_inner(
    rx: &mut mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
    socks_udp: Arc<UdpSocket>,
    dial: Dial,
    metrics: &UdpMetrics,
    idle: Duration,
    pool: &Arc<PacketQuota>,
) -> Result<AssocEnd, SessionError> {
    let (mut snell, mut codec) =
        dial_and_codec(dial.server, &dial.psk, dial.version, &dial.kdf).await?;
    let mut recv = pool.buffers.get(snell_protocol::V6_WIRE_CAP);
    with_codec!(&mut codec, |encoder, decoder| {
        open_udp(
            &mut snell,
            encoder,
            decoder,
            &pool.buffers,
            &mut recv,
            &dial.kdf,
            &dial.psk,
        )
        .await?;
        pump_client(
            &mut snell,
            encoder,
            decoder,
            &pool.buffers,
            &mut recv,
            &dial.kdf,
            &dial.psk,
            rx,
            peer,
            &socks_udp,
            metrics,
            idle,
            pool,
        )
        .await
    })
}

async fn open_udp<E: TcpEncoder, D: TcpDecoder>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    buffers: &Arc<BufferPool>,
    recv: &mut PooledBuffer,
    kdf: &crate::kdf::KdfLimiter,
    psk: &Psk,
) -> Result<(), SessionError> {
    crate::platform::prepare_session_stream(snell)?;
    with_handshake_timeout(async {
        write_udp_setup(encoder, buffers, snell).await?;
        let leftover = read_server_tunnel(decoder, recv, snell, kdf, psk).await?;
        if !leftover.is_empty() {
            return Err(SessionError::Protocol(Error::Malformed(
                "udp tunnel leftover",
            )));
        }
        Ok(())
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn pump_client<E, D>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    buffers: &Arc<BufferPool>,
    recv: &mut PooledBuffer,
    kdf: &crate::kdf::KdfLimiter,
    psk: &Psk,
    rx: &mut mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
    socks_udp: &UdpSocket,
    metrics: &UdpMetrics,
    idle: Duration,
    pool: &Arc<PacketQuota>,
) -> Result<AssocEnd, SessionError>
where
    E: TcpEncoder,
    D: TcpDecoder,
{
    let (mut snell_r, mut snell_w) = snell.split();
    let sleep = tokio::time::sleep(idle);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return Ok(AssocEnd::Idle),
            dgram = rx.recv() => {
                let Some(dgram) = dgram else {
                    return Ok(AssocEnd::Closed);
                };
                sleep.as_mut().reset(Instant::now() + idle);
                let payload = &dgram.buf.as_slice()[dgram.header_len..];
                let result = write_udp_request(
                    encoder,
                    buffers,
                    &mut snell_w,
                    dgram.dest.as_view(),
                    payload,
                )
                .await;
                match result {
                    Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                        metrics.oversize.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => return Err(error),
                    Ok(()) => {}
                }
            }
            record = decode_once(decoder, recv, &mut snell_r, kdf, psk) => {
                sleep.as_mut().reset(Instant::now() + idle);
                match record? {
                    RecordEvent::Zero => return Ok(AssocEnd::Closed),
                    RecordEvent::Data(record) => {
                        let plain = record.plaintext(recv.filled());
                        send_socks_response(socks_udp, peer, plain, metrics, pool).await?;
                        decoder.consume(recv, &record)?;
                    }
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
    pool: &Arc<PacketQuota>,
) -> Result<(), SessionError> {
    let pkt = match decode_udp_response(plain) {
        Ok(pkt) => pkt,
        Err(_) => {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    // Encode the SOCKS5 header on the stack, then append header and payload
    // into the pooled buffer: only the bytes actually sent are dirtied.
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
    let mut out = match pool.acquire(needed) {
        Some(buf) => buf,
        None => {
            metrics.no_buffer.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    out.extend(&hdr[..hdr_len])?;
    out.extend(pkt.payload)?;
    socks_udp.send_to(out.as_slice(), peer).await?;
    Ok(())
}

struct AssocGuard<'a>(&'a UdpMetrics);

impl Drop for AssocGuard<'_> {
    fn drop(&mut self) {
        self.0.associations.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_server_udp<E: TcpEncoder, D: TcpDecoder>(
    mut snell: TcpStream,
    mut encoder: E,
    mut decoder: D,
    outbound: Outbound,
    kdf: &crate::kdf::KdfLimiter,
    psk: &Psk,
    mut recv: PooledBuffer,
    udp: &UdpOptions,
) -> Result<(), SessionError> {
    let buffers = Arc::clone(recv.pool());
    let prev = udp.metrics.associations.fetch_add(1, Ordering::Relaxed);
    if prev >= udp.limits.max_associations as u64 {
        udp.metrics.associations.fetch_sub(1, Ordering::Relaxed);
        udp.metrics.map_full.fetch_add(1, Ordering::Relaxed);
        let _ = write_reject(&mut encoder, &buffers, &mut snell, "udp association limit").await;
        return Err(SessionError::UdpLimit);
    }
    let _guard = AssocGuard(&udp.metrics);

    let mut flow = match outbound.open_udp(&udp.dns, recv.pool()).await {
        Ok(flow) => flow,
        Err(error) => {
            let _ = write_reject(&mut encoder, &buffers, &mut snell, &error.to_string()).await;
            return Err(error);
        }
    };
    write_tunnel(&mut encoder, &buffers, &mut snell).await?;
    pump_server(
        &mut snell,
        &mut encoder,
        &mut decoder,
        &buffers,
        &mut recv,
        kdf,
        psk,
        &mut flow,
        udp,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn pump_server<E, D>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    buffers: &Arc<BufferPool>,
    recv: &mut PooledBuffer,
    kdf: &crate::kdf::KdfLimiter,
    psk: &Psk,
    flow: &mut crate::outbound::UdpFlow,
    udp: &UdpOptions,
) -> Result<(), SessionError>
where
    E: TcpEncoder,
    D: TcpDecoder,
{
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
            record = decode_once(decoder, recv, &mut snell_r, kdf, psk) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                match record? {
                    RecordEvent::Zero => return Ok(()),
                    RecordEvent::Data(record) => {
                        let plain = record.plaintext(recv.filled());
                        match decode_udp_request(plain) {
                            Ok(pkt) => {
                                if flow
                                    .send(pkt.address, pkt.payload, &udp.dns)
                                    .await
                                    .is_err()
                                {
                                    udp.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(_) => {
                                udp.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        decoder.consume(recv, &record)?;
                    }
                }
            }
            reply = flow.recv(&udp.metrics.frag_dropped, &udp.metrics.invalid) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                let reply = reply?;
                match write_udp_response(
                    encoder,
                    buffers,
                    &mut snell_w,
                    reply.addr.as_view(),
                    reply.payload(),
                )
                .await
                {
                    Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                        udp.metrics.oversize.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => return Err(error),
                    Ok(()) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn existing_association_routes_packets_and_releases_rejected_queue_items() {
        let pool = Arc::new(PacketQuota::new(Arc::default(), 2, 1024));
        let metrics = Arc::new(UdpMetrics::default());
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 3456));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (tx, mut rx) = mpsc::channel(1);
        let mut map = HashMap::from([(peer, AssocEntry { tx, control: 7 })]);
        let mut controls = HashMap::new();
        let (ctrl, _ctrl_rx) = mpsc::channel(1);
        let dial = Dial {
            server: peer,
            psk: Psk::new(b"0123456789abcdef").unwrap(),
            version: ProtocolFlavor::V4,
            kdf: Arc::new(KdfLimiter::new()),
        };
        let mut packet = [0u8; 64];
        let header =
            socks5::encode_udp_header(&mut packet, 0, snell_protocol::AddressRef::Ip(peer))
                .unwrap();
        packet[header..header + 4].copy_from_slice(b"ping");
        for _ in 0..2 {
            let mut buf = pool.acquire(header + 4).unwrap();
            buf.extend(&packet[..header + 4]).unwrap();
            handle_datagram(
                peer,
                buf,
                &mut map,
                &mut controls,
                &pool,
                &metrics,
                UdpLimits::default(),
                &dial,
                &socket,
                &ctrl,
            );
        }
        assert_eq!(map.len(), 1);
        assert_eq!(metrics.queue_full.load(Ordering::Relaxed), 1);
        assert_eq!(pool.live(), 1);
        let packet = rx.try_recv().unwrap();
        assert_eq!(&packet.buf.as_slice()[packet.header_len..], b"ping");
        drop(packet);
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.buffers.leased_bytes(), 0);
    }

    #[tokio::test]
    async fn failed_socks_response_returns_lease() {
        let pool = Arc::new(PacketQuota::new(Arc::default(), 2, 1024));
        let metrics = UdpMetrics::default();
        let mut plain = [0; 64];
        let n = snell_protocol::encode_udp_response(
            &mut plain,
            snell_protocol::AddressRef::Ip("127.0.0.1:9".parse().unwrap()),
            b"pong",
        )
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            send_socks_response(
                &socket,
                "[::1]:9".parse().unwrap(),
                &plain[..n],
                &metrics,
                &pool
            )
            .await
            .is_err()
        );
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.buffers.leased_bytes(), 0);
    }

    #[tokio::test]
    async fn assoc_dial_failure_releases_queued_buffers() {
        let pool = Arc::new(PacketQuota::new(Arc::default(), 4, 1024 * 1024));
        let (tx, rx) = mpsc::channel(4);
        for _ in 0..2 {
            let mut buf = pool.acquire(64).unwrap();
            buf.extend(b"ping").unwrap();
            tx.try_send(InboundDgram {
                dest: Address::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
                header_len: 0,
                buf,
            })
            .unwrap();
        }
        assert_eq!(pool.live(), 2);
        // Bind then drop: dialing this port fails fast with connection refused.
        let dead = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let socks_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
        let metrics = Arc::new(UdpMetrics::default());
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 3456));
        client_assoc(
            rx,
            peer,
            socks_udp,
            Dial {
                server: dead,
                psk: Psk::new(b"0123456789abcdef".to_vec()).unwrap(),
                version: ProtocolFlavor::V4,
                kdf: Arc::new(KdfLimiter::new()),
            },
            ctrl_tx,
            metrics,
            Duration::from_secs(5),
            pool.clone(),
        )
        .await;
        assert!(matches!(ctrl_rx.recv().await, Some(Ctrl::Closed(_))));
        assert_eq!(
            pool.live(),
            0,
            "queued datagram buffers must return to the pool when the association dies"
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
        let count = Arc::new(AtomicU64::new(0));
        let dispatcher = tokio::spawn(std::future::pending::<()>());
        let hub = UdpHub {
            bind: "127.0.0.1:1234".parse().unwrap(),
            _dispatcher: Arc::new(StopDispatcher(dispatcher.abort_handle())),
            ctrl,
            next_control: Arc::new(AtomicU64::new(1)),
            control_count: count.clone(),
            limits: UdpLimits::default(),
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
        assert_eq!(count.load(Ordering::Relaxed), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(matches!(rx.recv().await, Some(Ctrl::Remove(1))));
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_err(), "one removal only");
    }

    #[tokio::test]
    async fn control_drop_delivers_reserved_close_and_releases_count() {
        let (tx, mut rx) = mpsc::channel(2);
        let count = Arc::new(AtomicU64::new(1));
        let guard = ControlGuard {
            count: count.clone(),
            close: Some(tx.clone().reserve_owned().await.unwrap()),
            id: 7,
        };
        tx.send(Ctrl::Add(7)).await.unwrap();
        drop(guard);
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(matches!(rx.recv().await, Some(Ctrl::Add(7))));
        assert!(matches!(rx.recv().await, Some(Ctrl::Remove(7))));
    }
}

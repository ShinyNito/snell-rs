//! SOCKS5 UDP ASSOCIATE dispatcher and Snell UDP sessions.
//!
//! One dispatcher task owns `peer → association`. Lookup is `HashMap::get`.
//! Each association owns one Snell TCP. Idle uses a per-association `Sleep`,
//! not an O(N) map scan. Queue full is `try_send` failure plus a real counter.

use bytes::BufMut;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use snell_protocol::socks5::{self, Reply};
use snell_protocol::{
    Address, EncodeBuffer, Error, MAX_UDP_PACKET_ADDR_LEN, ProtocolFlavor, Psk, RecvBuffer,
    UDP_ASSOCIATION_IDLE_SECS, UDP_DATAGRAM_MAX, decode_udp_request, decode_udp_response,
};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::admission::Handshake;
use crate::client::dial_and_codec;
use crate::codec::{TcpDecoder, TcpEncoder};
use crate::dns::DnsResolver;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::packet::{PacketBuf, PacketPool};
use crate::pool::PooledCodec;
use crate::session::{
    RecordEvent, decode_once, new_encode, new_recv, read_server_tunnel, write_reject, write_tunnel,
    write_udp_request, write_udp_response, write_udp_setup,
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
}

struct InboundDgram {
    dest: Address,
    header_len: usize,
    buf: PacketBuf,
}

struct AssocEntry {
    tx: mpsc::Sender<InboundDgram>,
    control: ControlId,
    task: AbortHandle,
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
    controls: Arc<Semaphore>,
    _task: Arc<DispatcherTask>,
}

struct DispatcherTask(JoinHandle<()>);

impl Drop for DispatcherTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ControlLease {
    id: ControlId,
    remove: Option<mpsc::OwnedPermit<Ctrl>>,
    _slot: OwnedSemaphorePermit,
}

impl Drop for ControlLease {
    fn drop(&mut self) {
        if let Some(permit) = self.remove.take() {
            permit.send(Ctrl::Remove(self.id));
        }
    }
}

/// Local to one association, not a global atomic hot spot. The two futures
/// update actual I/O progress; the timer wakes only at a possible expiry.
struct Activity {
    start: Instant,
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }
    fn touch(&self) {
        self.last.store(
            self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }
    async fn expired(&self, idle: Duration) {
        loop {
            let deadline =
                self.start + Duration::from_nanos(self.last.load(Ordering::Relaxed)) + idle;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

impl UdpHub {
    pub async fn start(
        listen: SocketAddr,
        config: &crate::ClientConfig,
        kdf: Arc<KdfLimiter>,
    ) -> Result<Self, SessionError> {
        let socket = UdpSocket::bind(SocketAddr::new(listen.ip(), 0)).await?;
        let bind = socket.local_addr()?;
        let socket = Arc::new(socket);
        let limits = config.udp.limits;
        let metrics = config.udp.metrics.clone();
        let pool = Arc::new(PacketPool::new(limits.pool_bufs, limits.pool_bytes));
        let ctrl_cap = limits
            .max_controls
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .filter(|n| *n <= Semaphore::MAX_PERMITS)
            .ok_or_else(|| {
                SessionError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP control capacity is too large",
                ))
            })?;
        let (ctrl_tx, ctrl_rx) = mpsc::channel(ctrl_cap);
        let dial = Dial {
            server: config.server,
            psk: config.psk.clone(),
            version: config.version,
            kdf,
        };
        let task = tokio::spawn(dispatcher(
            socket,
            ctrl_rx,
            pool,
            metrics.clone(),
            limits,
            dial,
        ));
        Ok(Self {
            bind,
            ctrl: ctrl_tx,
            next_control: Arc::new(AtomicU64::new(1)),
            controls: Arc::new(Semaphore::new(limits.max_controls)),
            _task: Arc::new(DispatcherTask(task)),
        })
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind
    }

    pub async fn handle_associate(
        &self,
        mut local: TcpStream,
        mut handshake: Handshake,
    ) -> Result<(), SessionError> {
        let slot = match self.controls.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                handshake
                    .run(write_socks5_reply_bind(
                        &mut local,
                        Reply::GeneralFailure,
                        self.bind_addr(),
                    ))
                    .await??;
                return Err(SessionError::UdpLimit);
            }
        };
        let id = self.next_control.fetch_add(1, Ordering::Relaxed);
        // Reserve the removal message before publishing Add. Drop never has to
        // await or hope try_send succeeds when the control channel is full.
        let remove = handshake
            .run(async {
                self.ctrl
                    .clone()
                    .reserve_owned()
                    .await
                    .map_err(|_| SessionError::Cancelled)
            })
            .await??;
        handshake
            .run(async {
                self.ctrl
                    .send(Ctrl::Add(id))
                    .await
                    .map_err(|_| SessionError::Cancelled)
            })
            .await??;
        let _lease = ControlLease {
            id,
            remove: Some(remove),
            _slot: slot,
        };
        handshake
            .run(write_socks5_reply_bind(
                &mut local,
                Reply::Succeeded,
                self.bind_addr(),
            ))
            .await??;
        handshake.finish();
        let mut buf = [0u8; 1];
        while matches!(local.read(&mut buf).await, Ok(1..)) {}
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
    pool: Arc<PacketPool>,
    metrics: Arc<UdpMetrics>,
    limits: UdpLimits,
    dial: Dial,
) {
    let mut map: HashMap<SocketAddr, AssocEntry> = HashMap::new();
    let mut controls: HashMap<ControlId, Control> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut scratch = Vec::with_capacity(UDP_DATAGRAM_MAX);
    let mut held = pool.acquire(UDP_DATAGRAM_MAX);
    loop {
        if let Some(buf) = held.as_mut() {
            buf.clear();
        }
        scratch.clear();
        tokio::select! {
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { return; };
                apply_ctrl(ctrl, &mut map, &mut controls);
                if controls.is_empty() { pool.trim(); }
            }
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                if let Some(joined) = joined {
                    let ended = match joined {
                        Ok((id, peer)) => Some((id, peer)),
                        Err(error) => map.iter().find(|(_, entry)| entry.task.id() == error.id())
                            .map(|(peer, _)| (error.id(), *peer)),
                    };
                    if let Some((id, peer)) = ended
                        && map.get(&peer).is_some_and(|entry| entry.task.id() == id)
                        && let Some(entry) = map.remove(&peer)
                        && let Some(control) = controls.get_mut(&entry.control) {
                            control.peers.remove(&peer);
                    }
                }
            }
            result = async {
                match held.as_mut() {
                    Some(buf) => socket.recv_buf_from(buf).await,
                    None => socket.recv_buf_from(&mut scratch).await,
                }
            } => {
                if let Ok((_, peer)) = result {
                    if let Some(buf) = held.take() {
                        handle_datagram(peer, buf, &mut map, &mut controls, &metrics,
                            limits, &dial, &socket, &pool, &mut tasks);
                    } else {
                        metrics.no_buffer.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        if held.is_none() {
            held = pool.acquire(UDP_DATAGRAM_MAX);
        }
    }
}

fn apply_ctrl(
    ctrl: Ctrl,
    map: &mut HashMap<SocketAddr, AssocEntry>,
    controls: &mut HashMap<ControlId, Control>,
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
                    if let Some(entry) = map.remove(&peer) {
                        entry.task.abort();
                    }
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
    metrics: &Arc<UdpMetrics>,
    limits: UdpLimits,
    dial: &Dial,
    socket: &Arc<UdpSocket>,
    pool: &Arc<PacketPool>,
    tasks: &mut JoinSet<SocketAddr>,
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
    let dgram = InboundDgram {
        dest: packet.destination.into_owned(),
        header_len: packet.header_len,
        buf,
    };
    if let Some(entry) = map.get(&peer) {
        let _ = offer(&entry.tx, dgram, metrics);
        return;
    }
    if tasks.len() >= limits.max_associations {
        metrics.map_full.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(control) = pick_control(controls) else {
        metrics.invalid.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let (tx, rx) = mpsc::channel(limits.queue_max.max(1));
    if offer(&tx, dgram, metrics).is_err() {
        return;
    }
    metrics.associations.fetch_add(1, Ordering::Relaxed);
    let guard = AssocGuard(metrics.clone());
    let task = tasks.spawn(client_assoc(
        rx,
        peer,
        socket.clone(),
        dial.clone(),
        guard,
        limits.idle,
        pool.clone(),
    ));
    map.insert(peer, AssocEntry { tx, control, task });
    if let Some(slot) = controls.get_mut(&control) {
        slot.peers.insert(peer);
    }
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
    guard: AssocGuard,
    idle: Duration,
    pool: Arc<PacketPool>,
) -> SocketAddr {
    let metrics = &guard.0;
    if matches!(
        client_assoc_inner(&mut rx, peer, socks_udp, dial, metrics, idle, &pool).await,
        Ok(AssocEnd::Idle)
    ) {
        metrics.idle_expired.fetch_add(1, Ordering::Relaxed);
    }
    // Receiver drop releases queued leases; the guard also runs on task abort.
    peer
}

#[allow(clippy::too_many_arguments)]
async fn client_assoc_inner(
    rx: &mut mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
    socks_udp: Arc<UdpSocket>,
    dial: Dial,
    metrics: &UdpMetrics,
    idle: Duration,
    pool: &PacketPool,
) -> Result<AssocEnd, SessionError> {
    let handshake = Handshake::new(None);
    let (mut snell, codec) = handshake
        .run(dial_and_codec(
            dial.server,
            &dial.psk,
            dial.version,
            &dial.kdf,
        ))
        .await??;
    let mut encode = new_encode();
    let mut recv = new_recv();
    match codec {
        PooledCodec::V4 {
            mut encoder,
            mut decoder,
        } => {
            handshake
                .run(open_udp(
                    &mut snell,
                    &mut encoder,
                    &mut decoder,
                    &mut encode,
                    &mut recv,
                    &dial.kdf,
                    &dial.psk,
                ))
                .await??;
            pump_client(
                &mut snell,
                &mut encoder,
                &mut decoder,
                &mut encode,
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
        }
        PooledCodec::V6Shaped {
            mut encoder,
            mut decoder,
        } => {
            handshake
                .run(open_udp(
                    &mut snell,
                    &mut encoder,
                    &mut decoder,
                    &mut encode,
                    &mut recv,
                    &dial.kdf,
                    &dial.psk,
                ))
                .await??;
            pump_client(
                &mut snell,
                &mut encoder,
                &mut decoder,
                &mut encode,
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
        }
        PooledCodec::V6Unshaped {
            mut encoder,
            mut decoder,
        } => {
            handshake
                .run(open_udp(
                    &mut snell,
                    &mut encoder,
                    &mut decoder,
                    &mut encode,
                    &mut recv,
                    &dial.kdf,
                    &dial.psk,
                ))
                .await??;
            pump_client(
                &mut snell,
                &mut encoder,
                &mut decoder,
                &mut encode,
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
        }
    }
}

async fn open_udp<E: TcpEncoder, D: TcpDecoder>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    encode: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    kdf: &crate::kdf::KdfLimiter,
    psk: &Psk,
) -> Result<(), SessionError> {
    crate::platform::prepare_session_stream(snell)?;
    {
        write_udp_setup(encoder, encode, snell).await?;
        let leftover = read_server_tunnel(decoder, recv, snell, kdf, psk).await?;
        if !leftover.is_empty() {
            return Err(SessionError::Protocol(Error::Malformed(
                "udp tunnel leftover",
            )));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump_client<E, D>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    encode: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    kdf: &KdfLimiter,
    psk: &Psk,
    rx: &mut mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
    socks_udp: &UdpSocket,
    metrics: &UdpMetrics,
    idle: Duration,
    pool: &PacketPool,
) -> Result<AssocEnd, SessionError>
where
    E: TcpEncoder,
    D: TcpDecoder,
{
    let (mut snell_r, mut snell_w) = snell.split();
    let activity = Activity::new();
    let upload = async {
        while let Some(dgram) = rx.recv().await {
            let payload = &dgram.buf.as_slice()[dgram.header_len..];
            match write_udp_request(encoder, encode, &mut snell_w, dgram.dest.as_view(), payload)
                .await
            {
                Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                    metrics.oversize.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => return Err(error),
                Ok(()) => activity.touch(),
            }
        }
        Ok(AssocEnd::Closed)
    };
    let download = async {
        loop {
            match decode_once(decoder, recv, &mut snell_r, kdf, psk).await? {
                RecordEvent::Zero => return Ok(AssocEnd::Closed),
                RecordEvent::Data(record) => {
                    activity.touch();
                    send_socks_response(
                        socks_udp,
                        peer,
                        record.plaintext(recv.filled()),
                        metrics,
                        pool,
                    )
                    .await?;
                    decoder.consume(recv, &record)?;
                }
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
        _ = activity.expired(idle) => Ok(AssocEnd::Idle),
    }
}

async fn send_socks_response(
    socks_udp: &UdpSocket,
    peer: SocketAddr,
    plain: &[u8],
    metrics: &UdpMetrics,
    pool: &PacketPool,
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
    let capacity = needed.max(2048).next_power_of_two().min(UDP_DATAGRAM_MAX);
    let mut out = match pool.acquire(capacity) {
        Some(buf) => buf,
        None => {
            metrics.no_buffer.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    out.put_slice(&hdr[..hdr_len]);
    out.put_slice(pkt.payload);
    socks_udp.send_to(out.as_slice(), peer).await?;
    Ok(())
}

struct AssocGuard(Arc<UdpMetrics>);

impl Drop for AssocGuard {
    fn drop(&mut self) {
        self.0.associations.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_server_udp<E: TcpEncoder, D: TcpDecoder>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    outbound: Outbound,
    kdf: &crate::kdf::KdfLimiter,
    psk: &Psk,
    recv: &mut RecvBuffer,
    encode: &mut EncodeBuffer,
    udp: &UdpOptions,
    mut handshake: crate::admission::Handshake,
) -> Result<(), SessionError> {
    let prev = udp.metrics.associations.fetch_add(1, Ordering::Relaxed);
    if prev >= udp.limits.max_associations as u64 {
        udp.metrics.associations.fetch_sub(1, Ordering::Relaxed);
        udp.metrics.map_full.fetch_add(1, Ordering::Relaxed);
        let _ = handshake
            .run(write_reject(
                encoder,
                encode,
                snell,
                "udp association limit",
            ))
            .await?;
        return Err(SessionError::UdpLimit);
    }
    let _guard = AssocGuard(udp.metrics.clone());
    recv.raise_limit(snell_protocol::V6_WIRE_CAP);
    let flow = match handshake.run(outbound.open_udp(&udp.dns)).await? {
        Ok(flow) => flow,
        Err(error) => {
            let _ = handshake
                .run(write_reject(encoder, encode, snell, &error.to_string()))
                .await?;
            return Err(error);
        }
    };
    handshake
        .run(write_tunnel(encoder, encode, snell))
        .await??;
    handshake.finish();
    pump_server(snell, encoder, decoder, encode, recv, kdf, psk, &flow, udp).await
}

#[allow(clippy::too_many_arguments)]
async fn pump_server<E, D>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    encode: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    kdf: &KdfLimiter,
    psk: &Psk,
    flow: &crate::outbound::UdpFlow,
    udp: &UdpOptions,
) -> Result<(), SessionError>
where
    E: TcpEncoder,
    D: TcpDecoder,
{
    let (mut snell_r, mut snell_w) = snell.split();
    let activity = Activity::new();
    let upload = async {
        let mut send = Vec::new();
        loop {
            match decode_once(decoder, recv, &mut snell_r, kdf, psk).await? {
                RecordEvent::Zero => return Ok(()),
                RecordEvent::Data(record) => {
                    activity.touch();
                    let plain = record.plaintext(recv.filled());
                    match decode_udp_request(plain) {
                        Ok(pkt) => {
                            if flow
                                .send(pkt.address, pkt.payload, &udp.dns, &mut send)
                                .await
                                .is_err()
                            {
                                udp.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                            } else {
                                activity.touch();
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
    };
    let download = async {
        let mut packet = Vec::with_capacity(UDP_DATAGRAM_MAX);
        loop {
            let reply = flow
                .recv(&mut packet, &udp.metrics.frag_dropped, &udp.metrics.invalid)
                .await?;
            activity.touch();
            match write_udp_response(
                encoder,
                encode,
                &mut snell_w,
                reply.addr.as_view(),
                reply.payload,
            )
            .await
            {
                Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                    udp.metrics.oversize.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => return Err(error),
                Ok(()) => activity.touch(),
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
        _ = activity.expired(udp.limits.idle) => {
            udp.metrics.idle_expired.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn assoc_dial_failure_releases_queued_buffers() {
        let pool = Arc::new(PacketPool::new(4, 1024 * 1024));
        let (tx, rx) = mpsc::channel(4);
        for _ in 0..2 {
            let mut buf = pool.acquire(64).unwrap();
            buf.put_slice(b"ping");
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
            {
                metrics.associations.fetch_add(1, Ordering::Relaxed);
                AssocGuard(metrics)
            },
            Duration::from_secs(5),
            pool.clone(),
        )
        .await;
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
            buf: PacketBuf::from_test(vec![1, 2, 3]),
        };
        assert!(offer(&tx, dummy(), &metrics).is_ok());
        let second = offer(&tx, dummy(), &metrics);
        assert!(second.is_err(), "queue full must not report success");
        assert_eq!(metrics.queue_full.load(Ordering::Relaxed), 1);
    }
    #[tokio::test]
    async fn control_cancellation_delivers_reserved_remove_and_restores_slot() {
        let sem = Arc::new(Semaphore::new(1));
        let (tx, mut rx) = mpsc::channel(2);
        let permit = tx.clone().reserve_owned().await.unwrap();
        tx.send(Ctrl::Add(7)).await.unwrap();
        let lease = ControlLease {
            id: 7,
            remove: Some(permit),
            _slot: sem.clone().acquire_owned().await.unwrap(),
        };
        // No await is possible in Drop, but a full queue cannot lose Remove.
        drop(lease);
        assert_eq!(sem.available_permits(), 1);
        assert!(matches!(rx.recv().await, Some(Ctrl::Add(7))));
        assert!(matches!(rx.recv().await, Some(Ctrl::Remove(7))));
    }

    #[tokio::test]
    async fn slow_dns_does_not_block_udp_reply_or_idle_timeout() {
        use crate::outbound::UdpFlow;
        use snell_protocol::{V4Decoder, V4Encoder};
        let dns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let flow_addr = socket.local_addr().unwrap();
        let flow = UdpFlow::Direct { socket };
        let mut opts = UdpOptions::new().unwrap();
        opts.dns = DnsResolver::test_server(dns_socket.local_addr().unwrap());
        opts.limits.idle = Duration::from_millis(700);
        let metrics = opts.metrics.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let mut server = listener.accept().await.unwrap().0;
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let server_psk = psk.clone();
        let task = tokio::spawn(async move {
            let mut enc = V4Encoder::os(&server_psk).unwrap();
            let mut dec = V4Decoder::new(server_psk.clone());
            pump_server(
                &mut server,
                &mut enc,
                &mut dec,
                &mut new_encode(),
                &mut new_recv(),
                &KdfLimiter::new(),
                &server_psk,
                &flow,
                &opts,
            )
            .await
        });
        let mut enc = V4Encoder::os(&psk).unwrap();
        write_udp_request(
            &mut enc,
            &mut new_encode(),
            &mut client,
            snell_protocol::AddressRef::Domain {
                host: "pending.test.",
                port: 53,
            },
            b"query",
        )
        .await
        .unwrap();
        // Receiving the DNS query proves the upload branch is waiting in lookup.
        tokio::time::timeout(Duration::from_secs(2), dns_socket.recv_from(&mut [0; 2048]))
            .await
            .unwrap()
            .unwrap();
        let reply = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        reply
            .send_to(b"independent reply", flow_addr)
            .await
            .unwrap();
        let mut dec = V4Decoder::new(psk.clone());
        let mut recv = new_recv();
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            decode_once(&mut dec, &mut recv, &mut client, &KdfLimiter::new(), &psk),
        )
        .await
        .unwrap()
        .unwrap();
        let RecordEvent::Data(record) = result else {
            panic!("UDP data");
        };
        assert_eq!(
            decode_udp_response(record.plaintext(recv.filled()))
                .unwrap()
                .payload,
            b"independent reply"
        );
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(metrics.idle_expired.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn send_error_returns_output_lease() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = PacketPool::new(2, 4096);
        let mut plain = [0; 128];
        let n = snell_protocol::encode_udp_response(
            &mut plain,
            snell_protocol::AddressRef::Ip("127.0.0.1:53".parse().unwrap()),
            b"reply",
        )
        .unwrap();
        let result = send_socks_response(
            &socket,
            "[::1]:53".parse().unwrap(),
            &plain[..n],
            &UdpMetrics::default(),
            &pool,
        )
        .await;
        assert!(
            result.is_err(),
            "IPv4 socket cannot send to IPv6 destination"
        );
        assert_eq!(pool.live(), 0);
        assert!(pool.acquire(2048).is_some());
    }
}

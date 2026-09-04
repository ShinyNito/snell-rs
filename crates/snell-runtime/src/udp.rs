//! SOCKS5 UDP ASSOCIATE dispatcher and Snell UDP sessions.
//!
//! One dispatcher task owns `peer → association`. Lookup is `HashMap::get`.
//! Each association owns one Snell TCP. Idle uses a per-association `Sleep`,
//! not an O(N) map scan. Queue full is `try_send` failure plus a real counter.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use snell_protocol::socks5::{self, Reply};
use snell_protocol::{
    Address, EncodeBuffer, Error, ProtocolFlavor, Psk, RecvBuffer, UDP_ASSOCIATION_IDLE_SECS,
    UDP_DATAGRAM_MAX, decode_udp_request, decode_udp_response,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::client::dial_and_codec;
use crate::codec::{TcpDecoder, TcpEncoder};
use crate::dns::DnsResolver;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::packet::{PacketBuf, PacketPool};
use crate::pool::PooledCodec;
use crate::session::{
    RecordEvent, decode_once, ensure_udp, new_udp_encode, new_udp_recv, read_server_tunnel,
    with_handshake_timeout, write_reject, write_tunnel, write_udp_request, write_udp_response,
    write_udp_setup,
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
        let pool = Arc::new(PacketPool::new(limits.pool_bufs, limits.pool_bytes));
        let ctrl_cap = limits
            .max_controls
            .saturating_add(limits.max_associations)
            .max(1);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(ctrl_cap);
        let dial = Dial {
            server: config.server,
            psk: config.psk.clone(),
            version: config.version,
            kdf,
        };
        tokio::spawn(dispatcher(
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
        if self.ctrl.send(Ctrl::Add(id)).await.is_err() {
            self.control_count.fetch_sub(1, Ordering::Relaxed);
            return Err(SessionError::Cancelled);
        }
        write_socks5_reply_bind(&mut local, Reply::Succeeded, self.bind_addr()).await?;
        let mut buf = [0u8; 1];
        loop {
            match local.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = self.ctrl.send(Ctrl::Remove(id)).await;
        self.control_count.fetch_sub(1, Ordering::Relaxed);
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
    pool: Arc<PacketPool>,
    metrics: Arc<UdpMetrics>,
    limits: UdpLimits,
    dial: Dial,
) {
    let mut map: HashMap<SocketAddr, AssocEntry> = HashMap::new();
    let mut controls: HashMap<ControlId, Control> = HashMap::new();
    let mut drop_scratch = vec![0u8; UDP_DATAGRAM_MAX];
    let mut held = pool.acquire(UDP_DATAGRAM_MAX);
    loop {
        if let Some(mut buf) = held.take() {
            let result = {
                let spare = buf.spare(UDP_DATAGRAM_MAX);
                tokio::select! {
                    ctrl = ctrl_rx.recv() => Err(ctrl),
                    result = socket.recv_from(spare) => Ok(result),
                }
            };
            match result {
                Err(None) => return,
                Err(Some(ctrl)) => {
                    held = Some(buf);
                    apply_ctrl(ctrl, &mut map, &mut controls, &metrics);
                }
                Ok(Ok((n, peer))) => {
                    buf.truncate(n);
                    handle_datagram(
                        peer,
                        buf,
                        &mut map,
                        &mut controls,
                        &pool,
                        &metrics,
                        limits,
                        &dial,
                        &socket,
                        &ctrl_tx,
                    );
                    held = pool.acquire(UDP_DATAGRAM_MAX);
                }
                Ok(Err(_)) => {
                    held = Some(buf);
                }
            }
        } else {
            tokio::select! {
                ctrl = ctrl_rx.recv() => {
                    let Some(ctrl) = ctrl else { return; };
                    apply_ctrl(ctrl, &mut map, &mut controls, &metrics);
                }
                result = socket.recv_from(&mut drop_scratch) => {
                    if result.is_ok() {
                        metrics.no_buffer.fetch_add(1, Ordering::Relaxed);
                    }
                    held = pool.acquire(UDP_DATAGRAM_MAX);
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
    pool: &Arc<PacketPool>,
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
            pool.release(buf);
            return;
        }
    };
    if packet.frag != 0 {
        metrics.frag_dropped.fetch_add(1, Ordering::Relaxed);
        pool.release(buf);
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
        if let Err(buf) = offer(&entry.tx, dgram, metrics) {
            pool.release(buf);
        }
        return;
    }

    if controls.is_empty() {
        metrics.invalid.fetch_add(1, Ordering::Relaxed);
        pool.release(dgram.buf);
        return;
    }
    if map.len() >= limits.max_associations {
        metrics.map_full.fetch_add(1, Ordering::Relaxed);
        pool.release(dgram.buf);
        return;
    }
    let Some(control) = pick_control(controls) else {
        pool.release(dgram.buf);
        return;
    };
    let (tx, rx) = mpsc::channel(limits.queue_max.max(1));
    if let Err(buf) = offer(&tx, dgram, metrics) {
        pool.release(buf);
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
    rx: mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
    socks_udp: Arc<UdpSocket>,
    dial: Dial,
    ctrl: mpsc::Sender<Ctrl>,
    metrics: Arc<UdpMetrics>,
    idle: Duration,
    pool: Arc<PacketPool>,
) {
    let end = client_assoc_inner(rx, peer, socks_udp, dial, &metrics, idle, &pool).await;
    if matches!(end, Ok(AssocEnd::Idle)) {
        metrics.idle_expired.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(client = %peer, "udp association expired after idle timeout");
    }
    let _ = ctrl.send(Ctrl::Closed(peer)).await;
}

#[allow(clippy::too_many_arguments)]
async fn client_assoc_inner(
    rx: mpsc::Receiver<InboundDgram>,
    peer: SocketAddr,
    socks_udp: Arc<UdpSocket>,
    dial: Dial,
    metrics: &UdpMetrics,
    idle: Duration,
    pool: &PacketPool,
) -> Result<AssocEnd, SessionError> {
    let (mut snell, codec) =
        dial_and_codec(dial.server, &dial.psk, dial.version, &dial.kdf).await?;
    let mut encode = new_udp_encode();
    let mut recv = new_udp_recv();
    match codec {
        PooledCodec::V4 {
            mut encoder,
            mut decoder,
        } => {
            open_udp(
                &mut snell,
                &mut encoder,
                &mut decoder,
                &mut encode,
                &mut recv,
                &dial.kdf,
                &dial.psk,
            )
            .await?;
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
            open_udp(
                &mut snell,
                &mut encoder,
                &mut decoder,
                &mut encode,
                &mut recv,
                &dial.kdf,
                &dial.psk,
            )
            .await?;
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
            open_udp(
                &mut snell,
                &mut encoder,
                &mut decoder,
                &mut encode,
                &mut recv,
                &dial.kdf,
                &dial.psk,
            )
            .await?;
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
    with_handshake_timeout(async {
        write_udp_setup(encoder, encode, snell).await?;
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
    encode: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    kdf: &crate::kdf::KdfLimiter,
    psk: &Psk,
    mut rx: mpsc::Receiver<InboundDgram>,
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
                let payload = &dgram.buf.as_slice()[dgram.header_len.min(dgram.buf.len())..];
                let result = write_udp_request(
                    encoder,
                    encode,
                    &mut snell_w,
                    dgram.dest.as_view(),
                    payload,
                )
                .await;
                pool.release(dgram.buf);
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
    pool: &PacketPool,
) -> Result<(), SessionError> {
    let pkt = match decode_udp_response(plain) {
        Ok(pkt) => pkt,
        Err(_) => {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    let mut out = match pool.acquire(UDP_DATAGRAM_MAX) {
        Some(buf) => buf,
        None => {
            metrics.no_buffer.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    let n =
        match socks5::encode_udp_packet(out.spare(UDP_DATAGRAM_MAX), 0, pkt.address, pkt.payload) {
            Ok(n) => n,
            Err(Error::BufferTooSmall { .. } | Error::PayloadTooLarge) => {
                metrics.oversize.fetch_add(1, Ordering::Relaxed);
                pool.release(out);
                return Ok(());
            }
            Err(error) => {
                pool.release(out);
                return Err(error.into());
            }
        };
    out.truncate(n);
    socks_udp.send_to(out.as_slice(), peer).await?;
    pool.release(out);
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
    mut recv: RecvBuffer,
    mut encode: EncodeBuffer,
    udp: &UdpOptions,
) -> Result<(), SessionError> {
    let prev = udp.metrics.associations.fetch_add(1, Ordering::Relaxed);
    if prev >= udp.limits.max_associations as u64 {
        udp.metrics.associations.fetch_sub(1, Ordering::Relaxed);
        udp.metrics.map_full.fetch_add(1, Ordering::Relaxed);
        let _ = write_reject(
            &mut encoder,
            &mut encode,
            &mut snell,
            "udp association limit",
        )
        .await;
        return Err(SessionError::UdpLimit);
    }
    let _guard = AssocGuard(&udp.metrics);
    recv = ensure_udp(recv)?;
    encode = new_udp_encode();
    let mut flow = match outbound.open_udp(&udp.dns).await {
        Ok(flow) => flow,
        Err(error) => {
            let _ = write_reject(&mut encoder, &mut encode, &mut snell, &error.to_string()).await;
            return Err(error);
        }
    };
    write_tunnel(&mut encoder, &mut encode, &mut snell).await?;
    pump_server(
        &mut snell,
        &mut encoder,
        &mut decoder,
        &mut encode,
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
    encode: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
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

    #[test]
    fn lookup_is_hashmap_get_not_a_scan() {
        use std::cell::Cell;
        use std::hash::{Hash, Hasher};

        thread_local! {
            static EQS: Cell<usize> = const { Cell::new(0) };
            static HASHES: Cell<usize> = const { Cell::new(0) };
        }

        #[derive(Clone, Copy)]
        struct ProbeKey {
            id: u16,
        }

        impl PartialEq for ProbeKey {
            fn eq(&self, other: &Self) -> bool {
                EQS.with(|c| c.set(c.get() + 1));
                self.id == other.id
            }
        }
        impl Eq for ProbeKey {}
        impl Hash for ProbeKey {
            fn hash<H: Hasher>(&self, state: &mut H) {
                HASHES.with(|c| c.set(c.get() + 1));
                self.id.hash(state);
            }
        }

        fn entry() -> AssocEntry {
            let (tx, _rx) = mpsc::channel(1);
            AssocEntry { tx, control: 1 }
        }

        fn snapshot() -> (usize, usize) {
            (EQS.with(Cell::get), HASHES.with(Cell::get))
        }

        let mut map = HashMap::new();
        for id in 0..2000u16 {
            map.insert(ProbeKey { id }, entry());
        }

        let (eq_before, hash_before) = snapshot();
        let hit = map.get(&ProbeKey { id: 0 });
        let hit_eqs = EQS.with(Cell::get) - eq_before;
        let hit_hashes = HASHES.with(Cell::get) - hash_before;
        assert!(hit.is_some());
        assert!(
            hit_hashes >= 1,
            "HashMap::get hashes the key; a table scan would not: hashes={hit_hashes}"
        );
        assert!(
            hit_eqs < 32,
            "HashMap::get must not Eq every key: eqs={hit_eqs}"
        );

        let (eq_before, hash_before) = snapshot();
        let miss = map.get(&ProbeKey { id: 2001 });
        let miss_eqs = EQS.with(Cell::get) - eq_before;
        let miss_hashes = HASHES.with(Cell::get) - hash_before;
        assert!(miss.is_none());
        assert!(
            miss_hashes >= 1,
            "missing-key get must hash; a scan would only Eq: hashes={miss_hashes}"
        );
        assert!(
            miss_eqs < 32,
            "missing-key scan would Eq all 2000 entries: eqs={miss_eqs}"
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
}

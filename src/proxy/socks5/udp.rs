use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, sleep};

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::net::connect::connect_tcp;
use crate::protocol::psk::SnellPsk;
use crate::protocol::quic_proxy::{
    encode_init_datagram, is_quic_initial, is_quic_initial_packet, is_quic_looking,
    is_quic_short_header,
};
use crate::protocol::socks5::{SocksReply, parse_udp_packet, write_udp_packet};
use crate::protocol::udp::{AddressRef, parse_udp_response, write_udp_request_prefix};
use crate::proxy::outbound::RelayStats;
use crate::proxy::socks5::inbound::{write_reply_and_shutdown, write_reply_with_bind};
use crate::session::udp::io::{
    MAX_SOCKS_UDP_HEADER, SnellUdpPacketKind, UdpRecvBatch, UdpSendPacket,
    max_socks_udp_datagram_len, parse_socks_udp_header, reframe_socks_udp_packet, send_udp_batch,
};
use crate::session::udp::outbound::write_zero_chunk;
use crate::session::udp::stream::UdpClientStream;
use crate::{MAX_PACKET_SIZE, ProtocolVersion};

pub(super) const SOCKS5_UDP_ASSOCIATION_TIMEOUT: Duration = Duration::from_mins(1);
const SOCKS5_UDP_BUFFER_SIZE: usize = MAX_PACKET_SIZE + 512;
const MAX_QUIC_SOCKS_UDP_DATAGRAM: usize = MAX_SOCKS_UDP_HEADER + SOCKS5_UDP_BUFFER_SIZE;
type ClientPeerByUdpTarget = HashMap<OwnedUdpTarget, SocketAddr>;

struct FirstSocksUdpBuffers {
    socks_in: UdpRecvBatch,
}

struct FirstSocksDatagram {
    peer: SocketAddr,
    target: OwnedUdpTarget,
    payload_start: usize,
    payload_len: usize,
    datagram: BytesMut,
}

impl FirstSocksDatagram {
    /// The client payload (after the SOCKS5 UDP header) carried by this datagram.
    fn payload(&self) -> &[u8] {
        &self.datagram[self.payload_start..self.payload_start + self.payload_len]
    }
}

struct SnellUdpStartupBuffers {
    datagram: BytesMut,
    socks_header: BytesMut,
}

struct LazyQuicUdpBuffers {
    first_datagram: BytesMut,
    socks_in: UdpRecvBatch,
    quic_in: UdpRecvBatch,
    socks_header: BytesMut,
    plaintext: BytesMut,
    wire: BytesMut,
    quic_host_scratch: String,
}

struct SocksUdpOverSnellBuffers {
    socks_header: BytesMut,
    socks_in_batch: UdpRecvBatch,
}

impl FirstSocksUdpBuffers {
    fn new() -> Self {
        Self {
            socks_in: UdpRecvBatch::with_capacity(SOCKS5_UDP_BUFFER_SIZE, 1),
        }
    }
}

impl SnellUdpStartupBuffers {
    fn new(datagram: BytesMut) -> Self {
        Self {
            datagram,
            socks_header: BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER),
        }
    }
}

impl LazyQuicUdpBuffers {
    fn new(first_datagram: BytesMut) -> Self {
        Self {
            first_datagram,
            socks_in: UdpRecvBatch::with_capacity(SOCKS5_UDP_BUFFER_SIZE, 1),
            quic_in: UdpRecvBatch::with_capacity(MAX_PACKET_SIZE + 512, 1),
            socks_header: BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER),
            plaintext: BytesMut::with_capacity(MAX_PACKET_SIZE),
            wire: BytesMut::with_capacity(MAX_PACKET_SIZE + 512),
            quic_host_scratch: String::with_capacity(39),
        }
    }
}

impl SocksUdpOverSnellBuffers {
    fn new(socks_udp_limit: usize) -> Self {
        Self {
            socks_header: BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER),
            socks_in_batch: UdpRecvBatch::new(socks_udp_limit),
        }
    }
}

pub(crate) async fn relay_socks5_udp_association(
    mut control: TcpStream,
    server_addr: SocketAddr,
    secret: SnellPsk,
    version: ProtocolVersion,
    quic_proxy: bool,
) -> Result<RelayStats> {
    if quic_proxy && version == ProtocolVersion::V5 {
        return relay_socks5_udp_association_lazy_quic(control, server_addr, secret).await;
    }

    let control_peer_ip = control.peer_addr()?.ip();
    let udp_socket = bind_socks5_udp_socket(control.local_addr()?).await?;
    let udp_bind_addr = udp_socket.local_addr()?;
    let snell_tcp = match connect_tcp(server_addr).await {
        Ok(stream) => {
            stream.set_nodelay(true)?;
            stream
        }
        Err(err) => {
            write_reply_and_shutdown(&mut control, SocksReply::GeneralFailure).await;
            return Err(err.into());
        }
    };
    let (snell_reader_io, snell_writer_io) = snell_tcp.into_split();
    let snell =
        match UdpClientStream::open_io(snell_reader_io, snell_writer_io, &secret, version).await {
            Ok(snell) => snell,
            Err(err) => {
                write_reply_and_shutdown(&mut control, SocksReply::GeneralFailure).await;
                return Err(err);
            }
        };

    write_reply_with_bind(&mut control, SocksReply::Succeeded, udp_bind_addr).await?;

    let (mut control_reader, _control_writer) = control.into_split();
    let (mut snell_reader, mut snell_writer) = snell.into_parts();
    relay_socks5_udp_over_snell(
        &mut control_reader,
        &udp_socket,
        control_peer_ip,
        &mut snell_reader,
        &mut snell_writer,
        SocksUdpOverSnellState::default(),
    )
    .await
}

/// SOCKS5 UDP associate that only opens the snell/quic-proxy path after the
/// first client datagram arrives, so an idle association costs nothing.
///
/// Dispatch is driven by the first byte of that datagram: a QUIC Initial
/// takes the lazy QUIC-proxy path, anything else opens a snell UDP tunnel.
async fn relay_socks5_udp_association_lazy_quic(
    mut control: TcpStream,
    server_addr: SocketAddr,
    secret: SnellPsk,
) -> Result<RelayStats> {
    let control_peer_ip = control.peer_addr()?.ip();
    let udp_socket = bind_socks5_udp_socket(control.local_addr()?).await?;
    let udp_bind_addr = udp_socket.local_addr()?;
    write_reply_with_bind(&mut control, SocksReply::Succeeded, udp_bind_addr).await?;

    let (mut control_reader, _control_writer) = control.into_split();

    let Some(first) =
        recv_first_lazy_quic_datagram(&mut control_reader, &udp_socket, control_peer_ip).await?
    else {
        return Ok(RelayStats::default());
    };

    if first
        .payload()
        .first()
        .is_some_and(|byte| is_quic_initial(*byte))
    {
        let quic_socket = UdpSocket::bind(quic_bind_addr(server_addr)).await?;
        relay_lazy_quic_proxy_packets(
            &mut control_reader,
            &udp_socket,
            &quic_socket,
            server_addr,
            control_peer_ip,
            &secret,
            first,
        )
        .await
    } else {
        relay_lazy_quic_first_over_snell(
            &mut control_reader,
            &udp_socket,
            control_peer_ip,
            server_addr,
            &secret,
            first,
        )
        .await
    }
}

/// Waits for the first client datagram. Returns `None` when the control
/// connection closes or the association idles out before any data arrives.
async fn recv_first_lazy_quic_datagram<R>(
    control_reader: &mut R,
    udp_socket: &UdpSocket,
    control_peer_ip: IpAddr,
) -> Result<Option<FirstSocksDatagram>>
where
    R: AsyncRead + Unpin,
{
    let mut buffers = Box::new(FirstSocksUdpBuffers::new());
    let idle = sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            result = wait_control_closed(control_reader) => {
                result?;
                return Ok(None);
            }
            recv_result = buffers.socks_in.recv_from(udp_socket) => {
                recv_result?;
                let Some(entry) = buffers.socks_in.get(0) else {
                    continue;
                };
                if entry.is_oversized() {
                    tracing::debug!("ignored oversized socks5 udp datagram");
                    continue;
                }
                let peer = entry.peer();
                if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
                    tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                    continue;
                }
                let (target, payload_start, payload_len) = {
                    let packet = match parse_udp_packet(entry.payload()) {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::debug!(%err, "ignored invalid socks5 udp datagram");
                            continue;
                        }
                    };
                    (
                        OwnedUdpTarget::from_ref(packet.address, packet.port),
                        packet.payload_span.start,
                        packet.payload.len(),
                    )
                };
                let datagram = BytesMut::from(entry.payload());
                return Ok(Some(FirstSocksDatagram {
                    peer,
                    target,
                    payload_start,
                    payload_len,
                    datagram,
                }));
            }
            () = &mut idle => {
                tracing::debug!("snell socks5 udp association idle timed out");
                return Ok(None);
            }
        }
    }
}

/// Non-QUIC first datagram: open a snell UDP tunnel and forward the first
/// packet before entering the shared snell-over-udp relay loop.
async fn relay_lazy_quic_first_over_snell<R>(
    control_reader: &mut R,
    udp_socket: &UdpSocket,
    control_peer_ip: IpAddr,
    server_addr: SocketAddr,
    secret: &SnellPsk,
    first: FirstSocksDatagram,
) -> Result<RelayStats>
where
    R: AsyncRead + Unpin,
{
    let FirstSocksDatagram {
        peer: first_peer,
        target,
        payload_start,
        payload_len,
        datagram,
    } = first;

    let mut buffers = Box::new(SnellUdpStartupBuffers::new(datagram));
    let snell_tcp = connect_tcp(server_addr).await?;
    snell_tcp.set_nodelay(true)?;
    let (snell_reader_io, snell_writer_io) = snell_tcp.into_split();
    let snell = UdpClientStream::open_io(
        snell_reader_io,
        snell_writer_io,
        secret,
        ProtocolVersion::V5,
    )
    .await?;
    let (mut snell_reader, mut snell_writer) = snell.into_parts();
    let mut client_peer_by_target = ClientPeerByUdpTarget::new();
    client_peer_by_target.insert(target.clone(), first_peer);

    rewrite_socks_datagram_as_snell_request(
        &mut buffers.datagram,
        payload_start,
        payload_len,
        target.address_ref(),
        target.port,
        &mut buffers.socks_header,
    )?;
    if buffers.datagram.len() > snell_writer.max_udp_application_payload_len() {
        return Err(Error::PayloadTooLarge);
    }
    snell_writer
        .write_payload_message_from_buffer(&mut buffers.datagram)
        .await?;

    relay_socks5_udp_over_snell(
        control_reader,
        udp_socket,
        control_peer_ip,
        &mut snell_reader,
        &mut snell_writer,
        SocksUdpOverSnellState {
            client_addr: Some(first_peer),
            client_peer_by_target,
            uploaded: payload_len as u64,
        },
    )
    .await
}

/// QUIC Initial first datagram: run the lazy QUIC-proxy relay, encoding
/// snell-over-quic datagrams toward `server_addr` and bridging responses
/// back to the socks5 client.
#[allow(clippy::too_many_lines)]
async fn relay_lazy_quic_proxy_packets<R>(
    control_reader: &mut R,
    udp_socket: &UdpSocket,
    quic_socket: &UdpSocket,
    server_addr: SocketAddr,
    control_peer_ip: IpAddr,
    secret: &SnellPsk,
    first: FirstSocksDatagram,
) -> Result<RelayStats>
where
    R: AsyncRead + Unpin,
{
    let FirstSocksDatagram {
        peer: first_peer,
        mut target,
        payload_start,
        payload_len,
        datagram,
    } = first;

    let mut buffers = Box::new(LazyQuicUdpBuffers::new(datagram));
    let first_payload = &buffers.first_datagram[payload_start..payload_start + payload_len];
    let mut client_addr = Some(first_peer);
    let mut uploaded = first_payload.len() as u64;
    let mut downloaded = 0;
    let mut quic_handshake_done = first_payload
        .first()
        .is_some_and(|first| is_quic_short_header(*first));
    encode_init_datagram(
        secret.as_bytes(),
        target.quic_init_host(&mut buffers.quic_host_scratch),
        target.port,
        first_payload,
        &mut buffers.plaintext,
        &mut buffers.wire,
    )?;
    send_udp_batch(
        quic_socket,
        &[UdpSendPacket::single(&buffers.wire, server_addr)],
        MAX_PACKET_SIZE + 512,
    )
    .await?;

    let idle = sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT);
    tokio::pin!(idle);
    idle.as_mut()
        .reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);

    loop {
        tokio::select! {
            result = wait_control_closed(control_reader) => {
                result?;
                break;
            }
            recv_result = buffers.socks_in.recv_from(udp_socket) => {
                recv_result?;
                let Some(entry) = buffers.socks_in.get(0) else {
                    continue;
                };
                if entry.is_oversized() {
                    tracing::debug!("ignored oversized socks5 udp datagram");
                    continue;
                }
                let peer = entry.peer();
                if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
                    tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                    continue;
                }
                let packet = match parse_udp_packet(entry.payload()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::debug!(%err, "ignored invalid socks5 udp datagram");
                        continue;
                    }
                };
                client_addr = Some(peer);
                let raw_quic_payload = packet.payload.first().copied().is_some_and(|first| {
                    if !is_quic_looking(first) {
                        return false;
                    }
                    if is_quic_short_header(first) {
                        quic_handshake_done = true;
                        return true;
                    }
                    !(is_quic_initial_packet(first) && quic_handshake_done)
                });
                if raw_quic_payload {
                    target.update(packet.address, packet.port);
                    send_udp_batch(
                        quic_socket,
                        &[UdpSendPacket::single(packet.payload, server_addr)],
                        MAX_PACKET_SIZE + 512,
                    )
                    .await?;
                } else if !packet.payload.is_empty() {
                    encode_init_datagram(
                        secret.as_bytes(),
                        quic_init_host(packet.address, &mut buffers.quic_host_scratch),
                        packet.port,
                        packet.payload,
                        &mut buffers.plaintext,
                        &mut buffers.wire,
                    )?;
                    target.update(packet.address, packet.port);
                    send_udp_batch(
                        quic_socket,
                        &[UdpSendPacket::single(&buffers.wire, server_addr)],
                        MAX_PACKET_SIZE + 512,
                    )
                    .await?;
                } else {
                    target.update(packet.address, packet.port);
                }
                uploaded += packet.payload.len() as u64;
                idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
            }
            recv_result = buffers.quic_in.recv_from(quic_socket) => {
                recv_result?;
                let Some(entry) = buffers.quic_in.get(0) else {
                    continue;
                };
                if entry.is_oversized() {
                    tracing::debug!("ignored oversized quic proxy response");
                    continue;
                }
                let peer = entry.peer();
                if peer != server_addr {
                    tracing::debug!(%peer, server = %server_addr, "ignored quic proxy response from unexpected peer");
                    continue;
                }
                if let Some(peer) = client_addr {
                    buffers.socks_header.clear();
                    write_udp_packet(&mut buffers.socks_header, target.address_ref(), target.port, &[])?;
                    send_udp_batch(
                        udp_socket,
                        &[UdpSendPacket::parts(&buffers.socks_header, entry.payload(), peer)],
                        MAX_QUIC_SOCKS_UDP_DATAGRAM,
                    )
                    .await?;
                    downloaded += entry.payload_len() as u64;
                    idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                }
            }
            () = &mut idle => {
                tracing::debug!("snell socks5 udp association idle timed out");
                break;
            }
        }
    }

    Ok(RelayStats {
        uploaded,
        downloaded,
    })
}

fn quic_bind_addr(server_addr: SocketAddr) -> SocketAddr {
    let bind_ip = if server_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(bind_ip, 0)
}

#[derive(Default)]
struct SocksUdpOverSnellState {
    client_addr: Option<SocketAddr>,
    client_peer_by_target: ClientPeerByUdpTarget,
    uploaded: u64,
}

async fn relay_socks5_udp_over_snell<C, R, W>(
    control_reader: &mut C,
    udp_socket: &UdpSocket,
    control_peer_ip: IpAddr,
    snell_reader: &mut SnellStreamReader<R>,
    snell_writer: &mut SnellStreamWriter<W>,
    mut state: SocksUdpOverSnellState,
) -> Result<RelayStats>
where
    C: AsyncRead + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let socks_udp_limit =
        max_socks_udp_datagram_len(snell_writer.max_udp_application_payload_len());
    let idle = sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT);
    tokio::pin!(idle);

    let mut downloaded = 0;
    let mut buffers = Box::new(SocksUdpOverSnellBuffers::new(socks_udp_limit));

    loop {
        tokio::select! {
            result = wait_control_closed(control_reader) => {
                result?;
                break;
            }
            result = forward_socks_udp_socket_packets(
                snell_writer,
                udp_socket,
                control_peer_ip,
                &mut buffers.socks_in_batch,
                &mut state.client_peer_by_target,
            ) => {
                if let Some((batch_uploaded, peer)) = result? {
                    state.client_addr = Some(peer);
                    state.uploaded += batch_uploaded as u64;
                    idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                }
            }
            packet = snell_reader.read_udp_response_message() => {
                match packet {
                    Ok(Some(message)) => {
                        let packet = match parse_udp_response(&message) {
                            Ok(packet) => packet,
                            Err(err) if err.is_invalid_udp_packet() => {
                                tracing::debug!(%err, "ignored invalid snell udp response");
                                continue;
                            }
                            Err(err) => return Err(err),
                        };
                        if let Some(peer) = client_peer_for_response(
                            &state.client_peer_by_target,
                            state.client_addr,
                            packet.address,
                            packet.port,
                        ) {
                            buffers.socks_header.clear();
                            write_udp_packet(
                                &mut buffers.socks_header,
                                packet.address,
                                packet.port,
                                &[],
                            )?;
                            send_udp_batch(
                                udp_socket,
                                &[UdpSendPacket::parts(
                                    &buffers.socks_header,
                                    packet.payload,
                                    peer,
                                )],
                                socks_udp_limit,
                            )
                            .await?;
                            downloaded += packet.payload.len() as u64;
                            idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                        }
                    }
                    Ok(None) => break,
                    Err(err) if err.is_invalid_udp_packet() => {
                        tracing::debug!(%err, "ignored invalid snell udp response");
                    }
                    Err(err) => return Err(err),
                }
            }
            () = &mut idle => {
                tracing::debug!("snell socks5 udp association idle timed out");
                break;
            }
        }
    }

    write_zero_chunk(snell_writer).await?;
    Ok(RelayStats {
        uploaded: state.uploaded,
        downloaded,
    })
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OwnedUdpTarget {
    address: OwnedUdpAddress,
    port: u16,
}

impl OwnedUdpTarget {
    fn from_ref(address: AddressRef<'_>, port: u16) -> Self {
        Self {
            address: OwnedUdpAddress::from_ref(address),
            port,
        }
    }

    fn update(&mut self, address: AddressRef<'_>, port: u16) {
        self.address.update(address);
        self.port = port;
    }

    fn address_ref(&self) -> AddressRef<'_> {
        self.address.as_ref()
    }

    fn quic_init_host<'a>(&'a self, scratch: &'a mut String) -> &'a str {
        quic_init_host(self.address_ref(), scratch)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum OwnedUdpAddress {
    Domain(String),
    Ip(IpAddr),
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

fn quic_init_host<'a>(address: AddressRef<'a>, scratch: &'a mut String) -> &'a str {
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

async fn forward_socks_udp_socket_packets<W>(
    snell_writer: &mut SnellStreamWriter<W>,
    udp_socket: &UdpSocket,
    control_peer_ip: IpAddr,
    recv_batch: &mut UdpRecvBatch,
    client_peer_by_target: &mut ClientPeerByUdpTarget,
) -> Result<Option<(usize, SocketAddr)>>
where
    W: AsyncWrite + Unpin,
{
    let max_snell_udp_payload_len = snell_writer.max_udp_application_payload_len();
    let socks_udp_limit = max_socks_udp_datagram_len(max_snell_udp_payload_len);
    let count = recv_batch.recv_from(udp_socket).await?;
    let mut uploaded = 0;
    let mut last_peer = None;

    for index in 0..count {
        let Some(entry) = recv_batch.get(index) else {
            continue;
        };
        let peer = entry.peer();
        if entry.is_oversized() || entry.datagram().len() > socks_udp_limit {
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
            let mut entry = recv_batch
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
            snell_writer
                .write_payload_message_from_buffer(entry.datagram_mut())
                .await?;
        }
        uploaded += payload_len;
        client_peer_by_target.insert(target, peer);
        last_peer = Some(peer);
    }

    Ok(last_peer.map(|peer| (uploaded, peer)))
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

fn rewrite_socks_datagram_as_snell_request(
    datagram: &mut BytesMut,
    payload_start: usize,
    payload_len: usize,
    address: AddressRef<'_>,
    port: u16,
    prefix: &mut BytesMut,
) -> Result<()> {
    prefix.clear();
    write_udp_request_prefix(prefix, address, port)?;
    let Some(prefix_start) = payload_start.checked_sub(prefix.len()) else {
        return Err(Error::InvalidSocksRequest);
    };

    datagram[prefix_start..payload_start].copy_from_slice(prefix);
    datagram.advance(prefix_start);
    datagram.truncate(prefix.len() + payload_len);
    Ok(())
}

async fn bind_socks5_udp_socket(control_addr: SocketAddr) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(SocketAddr::new(control_addr.ip(), 0)).await?)
}

async fn wait_control_closed<R>(control: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0; 128];
    loop {
        let n = control.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{OwnedUdpAddress, OwnedUdpTarget, quic_init_host};
    use crate::protocol::udp::AddressRef;

    #[test]
    fn owned_udp_target_keeps_ip_without_domain_state() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let target = OwnedUdpTarget::from_ref(AddressRef::Ip(ip), 443);

        assert_eq!(target.address, OwnedUdpAddress::Ip(ip));
        assert_eq!(target.address_ref(), AddressRef::Ip(ip));
        assert_eq!(target.port, 443);

        let mut scratch = String::with_capacity(39);
        assert_eq!(target.quic_init_host(&mut scratch), "1.2.3.4");
        assert_eq!(target.address_ref(), AddressRef::Ip(ip));
    }

    #[test]
    fn owned_udp_target_does_not_replace_same_domain() {
        let mut target = OwnedUdpTarget::from_ref(AddressRef::Domain("example.com"), 443);
        let before = match &target.address {
            OwnedUdpAddress::Domain(host) => host.as_ptr(),
            OwnedUdpAddress::Ip(_) => panic!("expected domain target"),
        };

        target.update(AddressRef::Domain("example.com"), 443);

        let after = match &target.address {
            OwnedUdpAddress::Domain(host) => host.as_ptr(),
            OwnedUdpAddress::Ip(_) => panic!("expected domain target"),
        };
        assert_eq!(before, after);
        assert_eq!(target.address_ref(), AddressRef::Domain("example.com"));
    }

    #[test]
    fn owned_udp_target_switches_address_kind_without_parsing() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut target = OwnedUdpTarget::from_ref(AddressRef::Domain("example.com"), 53);

        target.update(AddressRef::Ip(ip), 443);
        assert_eq!(target.address_ref(), AddressRef::Ip(ip));
        assert_eq!(target.port, 443);

        target.update(AddressRef::Domain("api.example.com"), 8443);
        assert_eq!(target.address_ref(), AddressRef::Domain("api.example.com"));
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn quic_init_host_borrows_domain_and_reuses_ip_scratch() {
        let mut scratch = String::from("unchanged");
        assert_eq!(
            quic_init_host(AddressRef::Domain("example.com"), &mut scratch),
            "example.com"
        );
        assert_eq!(scratch, "unchanged");

        assert_eq!(
            quic_init_host(
                AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                &mut scratch
            ),
            "::1"
        );
        assert_eq!(scratch, "::1");
    }
}

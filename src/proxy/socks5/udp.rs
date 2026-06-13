use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, sleep};

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::net::connect::connect_tcp;
use crate::protocol::quic_proxy::{
    encode_init_datagram, is_quic_initial, is_quic_initial_packet, is_quic_looking,
    is_quic_short_header,
};
use crate::protocol::socks5::{SocksReply, parse_udp_packet, write_udp_packet};
use crate::protocol::udp::{AddressRef, parse_udp_response, write_udp_request_prefix};
use crate::proxy::outbound::RelayStats;
use crate::proxy::socks5::inbound::{write_reply_and_shutdown, write_reply_with_bind};
use crate::session::udp::io::{
    MAX_SOCKS_UDP_HEADER, SnellUdpPacketKind, max_socks_udp_datagram_len, parse_socks_udp_header,
    recv_socks_udp_datagram_into, recv_udp_datagram_into, reframe_socks_udp_packet, send_udp_parts,
};
use crate::session::udp::outbound::write_zero_chunk;
use crate::session::udp::stream::UdpClientStream;
use crate::{MAX_PACKET_SIZE, ProtocolVersion};

pub(super) const SOCKS5_UDP_ASSOCIATION_TIMEOUT: Duration = Duration::from_secs(60);
const SOCKS5_UDP_BUFFER_SIZE: usize = MAX_PACKET_SIZE + 512;
const MAX_QUIC_SOCKS_UDP_DATAGRAM: usize = MAX_SOCKS_UDP_HEADER + SOCKS5_UDP_BUFFER_SIZE;

pub(crate) async fn relay_socks5_udp_association(
    mut control: TcpStream,
    server_addr: SocketAddr,
    psk: &[u8],
    version: ProtocolVersion,
    quic_proxy: bool,
) -> Result<RelayStats> {
    if quic_proxy && version == ProtocolVersion::V5 {
        return Box::pin(relay_socks5_udp_association_lazy_quic(
            control,
            server_addr,
            psk,
        ))
        .await;
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
    let snell = match UdpClientStream::open_io(snell_reader_io, snell_writer_io, psk, version).await
    {
        Ok(snell) => snell,
        Err(err) => {
            write_reply_and_shutdown(&mut control, SocksReply::GeneralFailure).await;
            return Err(err);
        }
    };

    write_reply_with_bind(&mut control, SocksReply::Succeeded, udp_bind_addr).await?;

    let (mut control_reader, _control_writer) = control.into_split();
    let (mut snell_reader, mut snell_writer) = snell.into_parts();
    let socks_udp_limit =
        max_socks_udp_datagram_len(snell_writer.max_udp_application_payload_len());
    let idle = sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT);
    tokio::pin!(idle);

    let mut uploaded = 0;
    let mut downloaded = 0;
    let mut client_addr = None;
    let mut socks_header = BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER);
    let mut socks_packet = BytesMut::new();
    let mut snell_udp_message = BytesMut::new();

    loop {
        tokio::select! {
            result = wait_control_closed(&mut control_reader) => {
                result?;
                break;
            }
            result = forward_socks_udp_socket_packet(&mut snell_writer, &udp_socket, control_peer_ip) => {
                match result? {
                    Some((payload_len, peer)) => {
                        client_addr = Some(peer);
                        uploaded += payload_len as u64;
                        idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                    }
                    None => continue,
                }
            }
            packet = read_snell_udp_response(&mut snell_reader, &mut snell_udp_message) => {
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
                        if let Some(peer) = client_addr {
                            socks_header.clear();
                            write_udp_packet(&mut socks_header, packet.address, packet.port, &[])?;
                            send_udp_parts(
                                &udp_socket,
                                &socks_header,
                                packet.payload,
                                peer,
                                socks_udp_limit,
                                &mut socks_packet,
                            )
                            .await?;
                            downloaded += packet.payload.len() as u64;
                            idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                        }
                    }
                    Ok(None) => break,
                    Err(err) if err.is_invalid_udp_packet() => {
                        tracing::debug!(%err, "ignored invalid snell udp response");
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
            _ = &mut idle => {
                tracing::debug!("snell socks5 udp association idle timed out");
                break;
            }
        }
    }

    write_zero_chunk(&mut snell_writer).await?;
    Ok(RelayStats {
        uploaded,
        downloaded,
    })
}

async fn relay_socks5_udp_association_lazy_quic(
    mut control: TcpStream,
    server_addr: SocketAddr,
    psk: &[u8],
) -> Result<RelayStats> {
    let control_peer_ip = control.peer_addr()?.ip();
    let udp_socket = bind_socks5_udp_socket(control.local_addr()?).await?;
    let udp_bind_addr = udp_socket.local_addr()?;
    write_reply_with_bind(&mut control, SocksReply::Succeeded, udp_bind_addr).await?;

    let (mut control_reader, _control_writer) = control.into_split();
    let idle = sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT);
    tokio::pin!(idle);

    let mut first_socks_in = BytesMut::with_capacity(SOCKS5_UDP_BUFFER_SIZE);
    let first = loop {
        tokio::select! {
            result = wait_control_closed(&mut control_reader) => {
                result?;
                return Ok(RelayStats::default());
            }
            recv_result = recv_udp_datagram_into(&udp_socket, &mut first_socks_in, SOCKS5_UDP_BUFFER_SIZE) => {
                let (n, peer) = match recv_result {
                    Ok(result) => result,
                    Err(Error::PayloadTooLarge) => {
                        tracing::debug!("ignored oversized socks5 udp datagram");
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
                    tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                    first_socks_in.clear();
                    continue;
                }
                let (target, payload_start, payload_len) = {
                    let packet = match parse_udp_packet(&first_socks_in[..n]) {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::debug!(%err, "ignored invalid socks5 udp datagram");
                            first_socks_in.clear();
                            continue;
                        }
                    };
                    (
                        OwnedUdpTarget::from_ref(packet.address, packet.port),
                        packet.payload_span.start,
                        packet.payload.len(),
                    )
                };
                first_socks_in.truncate(n);
                break (peer, target, payload_start, payload_len, first_socks_in);
            }
            _ = &mut idle => {
                tracing::debug!("snell socks5 udp association idle timed out");
                return Ok(RelayStats::default());
            }
        }
    };

    let (first_peer, mut target, first_payload_start, first_payload_len, mut first_datagram) =
        first;
    let mut client_addr = Some(first_peer);
    let mut socks_in = BytesMut::with_capacity(SOCKS5_UDP_BUFFER_SIZE);

    if !first_datagram[first_payload_start..first_payload_start + first_payload_len]
        .first()
        .is_some_and(|first| is_quic_initial(*first))
    {
        let snell_tcp = connect_tcp(server_addr).await?;
        snell_tcp.set_nodelay(true)?;
        let (snell_reader_io, snell_writer_io) = snell_tcp.into_split();
        let snell =
            UdpClientStream::open_io(snell_reader_io, snell_writer_io, psk, ProtocolVersion::V5)
                .await?;
        let (mut snell_reader, mut snell_writer) = snell.into_parts();
        let socks_udp_limit =
            max_socks_udp_datagram_len(snell_writer.max_udp_application_payload_len());
        let mut socks_header = BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER);
        let mut socks_packet = BytesMut::new();
        let mut snell_udp_message = BytesMut::new();
        let mut uploaded = first_payload_len as u64;
        let mut downloaded = 0;

        rewrite_socks_datagram_as_snell_request(
            &mut first_datagram,
            first_payload_start,
            first_payload_len,
            target.address_ref(),
            target.port,
        )?;
        snell_writer
            .write_owned_udp_payload_message(first_datagram)
            .await?;
        idle.as_mut()
            .reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);

        loop {
            tokio::select! {
                result = wait_control_closed(&mut control_reader) => {
                    result?;
                    break;
                }
                result = forward_socks_udp_socket_packet(&mut snell_writer, &udp_socket, control_peer_ip) => {
                    match result? {
                        Some((payload_len, peer)) => {
                            client_addr = Some(peer);
                            uploaded += payload_len as u64;
                            idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                        }
                        None => continue,
                    }
                }
                packet = read_snell_udp_response(&mut snell_reader, &mut snell_udp_message) => {
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
                            if let Some(peer) = client_addr {
                                socks_header.clear();
                                write_udp_packet(&mut socks_header, packet.address, packet.port, &[])?;
                                send_udp_parts(
                                    &udp_socket,
                                    &socks_header,
                                    packet.payload,
                                    peer,
                                    socks_udp_limit,
                                    &mut socks_packet,
                                )
                                .await?;
                                downloaded += packet.payload.len() as u64;
                                idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                            }
                        }
                        Ok(None) => break,
                        Err(err) if err.is_invalid_udp_packet() => {
                            tracing::debug!(%err, "ignored invalid snell udp response");
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
                _ = &mut idle => {
                    tracing::debug!("snell socks5 udp association idle timed out");
                    break;
                }
            }
        }

        write_zero_chunk(&mut snell_writer).await?;
        return Ok(RelayStats {
            uploaded,
            downloaded,
        });
    }

    let first_payload =
        &first_datagram[first_payload_start..first_payload_start + first_payload_len];
    let bind_ip = if server_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let quic_socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let mut uploaded = first_payload.len() as u64;
    let mut downloaded = 0;
    let mut quic_in = BytesMut::with_capacity(MAX_PACKET_SIZE + 512);
    let mut socks_header = BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER);
    let mut socks_packet = BytesMut::new();
    let mut plaintext = BytesMut::with_capacity(MAX_PACKET_SIZE);
    let mut wire = BytesMut::with_capacity(MAX_PACKET_SIZE + 512);
    let mut quic_host_scratch = String::with_capacity(39);
    let mut quic_handshake_done = first_payload
        .first()
        .is_some_and(|first| is_quic_short_header(*first));
    encode_init_datagram(
        psk,
        target.quic_init_host(&mut quic_host_scratch),
        target.port,
        first_payload,
        &mut plaintext,
        &mut wire,
    )?;
    quic_socket.send_to(&wire, server_addr).await?;
    idle.as_mut()
        .reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);

    loop {
        tokio::select! {
            result = wait_control_closed(&mut control_reader) => {
                result?;
                break;
            }
            recv_result = recv_udp_datagram_into(&udp_socket, &mut socks_in, SOCKS5_UDP_BUFFER_SIZE) => {
                let (n, peer) = match recv_result {
                    Ok(result) => result,
                    Err(Error::PayloadTooLarge) => {
                        tracing::debug!("ignored oversized socks5 udp datagram");
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
                    tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                    continue;
                }
                let packet = match parse_udp_packet(&socks_in[..n]) {
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
                    quic_socket.send_to(packet.payload, server_addr).await?;
                } else if !packet.payload.is_empty() {
                    encode_init_datagram(
                        psk,
                        quic_init_host(packet.address, &mut quic_host_scratch),
                        packet.port,
                        packet.payload,
                        &mut plaintext,
                        &mut wire,
                    )?;
                    target.update(packet.address, packet.port);
                    quic_socket.send_to(&wire, server_addr).await?;
                } else {
                    target.update(packet.address, packet.port);
                }
                uploaded += packet.payload.len() as u64;
                idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
            }
            recv_result = recv_udp_datagram_into(&quic_socket, &mut quic_in, MAX_PACKET_SIZE + 512) => {
                let (n, peer) = match recv_result {
                    Ok(result) => result,
                    Err(Error::PayloadTooLarge) => {
                        tracing::debug!("ignored oversized quic proxy response");
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                if peer != server_addr {
                    tracing::debug!(%peer, server = %server_addr, "ignored quic proxy response from unexpected peer");
                    continue;
                }
                if let Some(peer) = client_addr {
                    socks_header.clear();
                    write_udp_packet(&mut socks_header, target.address_ref(), target.port, &[])?;
                    send_udp_parts(
                        &udp_socket,
                        &socks_header,
                        &quic_in[..n],
                        peer,
                        MAX_QUIC_SOCKS_UDP_DATAGRAM,
                        &mut socks_packet,
                    )
                    .await?;
                    downloaded += n as u64;
                    idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                }
            }
            _ = &mut idle => {
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

async fn forward_socks_udp_socket_packet<W>(
    snell_writer: &mut SnellStreamWriter<W>,
    udp_socket: &UdpSocket,
    control_peer_ip: IpAddr,
) -> Result<Option<(usize, SocketAddr)>>
where
    W: AsyncWrite + Unpin,
{
    let frame_len;
    let payload_len;
    let peer;
    let max_snell_udp_payload_len = snell_writer.max_udp_application_payload_len();
    let socks_udp_limit = max_socks_udp_datagram_len(max_snell_udp_payload_len);
    {
        let frame = snell_writer.start_payload_frame();
        let datagram_len =
            match recv_socks_udp_datagram_into(udp_socket, frame, socks_udp_limit).await {
                Ok((datagram_len, recv_peer)) => {
                    peer = recv_peer;
                    datagram_len
                }
                Err(Error::PayloadTooLarge) => {
                    tracing::debug!("ignored oversized socks5 udp datagram");
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
        if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
            tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
            return Ok(None);
        }

        let header = match parse_socks_udp_header(&frame[..datagram_len]) {
            Ok(header) => header,
            Err(err) => {
                tracing::debug!(%err, "ignored invalid socks5 udp datagram");
                return Ok(None);
            }
        };
        payload_len = header.payload_len();
        let prefix_start = match reframe_socks_udp_packet(
            frame,
            &header,
            SnellUdpPacketKind::Request,
            max_snell_udp_payload_len,
        ) {
            Ok(prefix_start) => prefix_start,
            Err(Error::PayloadTooLarge) => {
                tracing::debug!("ignored oversized socks5 udp datagram");
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        frame.advance(prefix_start);
        frame_len = frame.len();
    }

    snell_writer.finish_udp_payload_message(frame_len).await?;
    Ok(Some((payload_len, peer)))
}

fn rewrite_socks_datagram_as_snell_request(
    datagram: &mut BytesMut,
    payload_start: usize,
    payload_len: usize,
    address: AddressRef<'_>,
    port: u16,
) -> Result<()> {
    let mut prefix = BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER);
    write_udp_request_prefix(&mut prefix, address, port)?;
    let Some(prefix_start) = payload_start.checked_sub(prefix.len()) else {
        return Err(Error::InvalidSocksRequest);
    };

    datagram[prefix_start..payload_start].copy_from_slice(&prefix);
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

async fn read_snell_udp_response<R>(
    reader: &mut SnellStreamReader<R>,
    scratch: &mut BytesMut,
) -> Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    reader.read_udp_response_message(scratch).await
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

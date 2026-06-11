use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, sleep};

use crate::error::{Error, Result};
use crate::protocol::quic_proxy::{
    encode_init_datagram, is_quic_initial, is_quic_initial_packet, is_quic_looking,
    is_quic_short_header,
};
use crate::protocol::socks5::{SocksReply, parse_udp_packet, write_udp_packet};
use crate::protocol::udp::{AddressRef, UdpPacketRef, parse_udp_response};
use crate::service::inbound::socks5::{write_reply_and_shutdown, write_reply_with_bind};
use crate::service::outbound::RelayStats;
use crate::service::runtime::net::connect_tcp;
use crate::service::session::udp_outbound::write_zero_chunk;
use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};
use crate::transport::udp_stream::UdpClientStream;
use crate::{MAX_PACKET_SIZE, VERSION_5};

pub(super) const SOCKS5_UDP_ASSOCIATION_TIMEOUT: Duration = Duration::from_secs(60);
const SOCKS5_UDP_BUFFER_SIZE: usize = MAX_PACKET_SIZE + 512;

pub(crate) async fn relay_socks5_udp_association(
    mut control: TcpStream,
    server_addr: SocketAddr,
    psk: &[u8],
    version: u8,
    quic_proxy: bool,
) -> Result<RelayStats> {
    if quic_proxy && version == VERSION_5 {
        return relay_socks5_udp_association_lazy_quic(control, server_addr, psk).await;
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
    let idle = sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT);
    tokio::pin!(idle);

    let mut uploaded = 0;
    let mut downloaded = 0;
    let mut client_addr = None;
    let mut socks_in = [0; SOCKS5_UDP_BUFFER_SIZE];
    let mut socks_out = BytesMut::with_capacity(SOCKS5_UDP_BUFFER_SIZE);

    loop {
        tokio::select! {
            result = wait_control_closed(&mut control_reader) => {
                result?;
                break;
            }
            recv_result = udp_socket.recv_from(&mut socks_in) => {
                let (n, peer) = recv_result?;
                if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
                    tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                    continue;
                }
                client_addr = Some(peer);
                match forward_socks_udp_packet(&mut snell_writer, &socks_in[..n]).await? {
                    Some(payload_len) => {
                        uploaded += payload_len as u64;
                        idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                    }
                    None => continue,
                }
            }
            packet = read_snell_udp_response(&mut snell_reader) => {
                match packet {
                    Ok(Some(packet)) => {
                        if let Some(peer) = client_addr {
                            socks_out.clear();
                            write_udp_packet(&mut socks_out, packet.address, packet.port, packet.payload)?;
                            udp_socket.send_to(&socks_out, peer).await?;
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
            recv_result = udp_socket.recv_buf_from(&mut first_socks_in) => {
                let (n, peer) = recv_result?;
                if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
                    tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                    first_socks_in.clear();
                    continue;
                }
                let payload_start = {
                    let packet = match parse_udp_packet(&first_socks_in[..n]) {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::debug!(%err, "ignored invalid socks5 udp datagram");
                            first_socks_in.clear();
                            continue;
                        }
                    };
                    packet.payload_span.start
                };
                let payload = first_socks_in.split_off(payload_start).freeze();
                let packet = parse_udp_packet(&first_socks_in)?;
                break (
                    peer,
                    packet.address,
                    packet.port,
                    payload,
                );
            }
            _ = &mut idle => {
                tracing::debug!("snell socks5 udp association idle timed out");
                return Ok(RelayStats::default());
            }
        }
    };

    let (first_peer, first_address, first_port, first_payload) = first;
    let mut client_addr = Some(first_peer);
    let mut socks_in = [0; SOCKS5_UDP_BUFFER_SIZE];

    if !first_payload
        .first()
        .is_some_and(|first| is_quic_initial(*first))
    {
        let snell_tcp = connect_tcp(server_addr).await?;
        snell_tcp.set_nodelay(true)?;
        let (snell_reader_io, snell_writer_io) = snell_tcp.into_split();
        let snell =
            UdpClientStream::open_io(snell_reader_io, snell_writer_io, psk, VERSION_5).await?;
        let (mut snell_reader, mut snell_writer) = snell.into_parts();
        let mut socks_out = BytesMut::with_capacity(SOCKS5_UDP_BUFFER_SIZE);
        let mut uploaded = first_payload.len() as u64;
        let mut downloaded = 0;

        snell_writer
            .write_udp_packet(first_address, first_port, &first_payload)
            .await?;
        idle.as_mut()
            .reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);

        loop {
            tokio::select! {
                result = wait_control_closed(&mut control_reader) => {
                    result?;
                    break;
                }
                recv_result = udp_socket.recv_from(&mut socks_in) => {
                    let (n, peer) = recv_result?;
                    if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
                        tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                        continue;
                    }
                    client_addr = Some(peer);
                    match forward_socks_udp_packet(&mut snell_writer, &socks_in[..n]).await? {
                        Some(payload_len) => {
                            uploaded += payload_len as u64;
                            idle.as_mut().reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                        }
                        None => continue,
                    }
                }
                packet = read_snell_udp_response(&mut snell_reader) => {
                    match packet {
                        Ok(Some(packet)) => {
                            if let Some(peer) = client_addr {
                                socks_out.clear();
                                write_udp_packet(&mut socks_out, packet.address, packet.port, packet.payload)?;
                                udp_socket.send_to(&socks_out, peer).await?;
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

    let bind_ip = if server_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let quic_socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let mut target = OwnedUdpTarget::from_ref(first_address, first_port);
    let mut uploaded = first_payload.len() as u64;
    let mut downloaded = 0;
    let mut quic_in = [0; MAX_PACKET_SIZE + 512];
    let mut socks_out = BytesMut::with_capacity(SOCKS5_UDP_BUFFER_SIZE);
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
        &first_payload,
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
            recv_result = udp_socket.recv_from(&mut socks_in) => {
                let (n, peer) = recv_result?;
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
            recv_result = quic_socket.recv_from(&mut quic_in) => {
                let (n, peer) = recv_result?;
                if peer != server_addr {
                    tracing::debug!(%peer, server = %server_addr, "ignored quic proxy response from unexpected peer");
                    continue;
                }
                if let Some(peer) = client_addr {
                    socks_out.clear();
                    write_udp_packet(&mut socks_out, target.address_ref(), target.port, &quic_in[..n])?;
                    udp_socket.send_to(&socks_out, peer).await?;
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

async fn forward_socks_udp_packet<W>(
    snell_writer: &mut V4StreamWriter<W>,
    packet: &[u8],
) -> Result<Option<usize>>
where
    W: AsyncWrite + Unpin,
{
    let packet = match parse_udp_packet(packet) {
        Ok(packet) => packet,
        Err(err) => {
            tracing::debug!(%err, "ignored invalid socks5 udp datagram");
            return Ok(None);
        }
    };

    match snell_writer
        .write_udp_packet(packet.address, packet.port, packet.payload)
        .await
    {
        Ok(_) => Ok(Some(packet.payload.len())),
        Err(Error::PayloadTooLarge) => {
            tracing::debug!(
                payload_len = packet.payload.len(),
                "ignored oversized socks5 udp datagram"
            );
            Ok(None)
        }
        Err(err) => Err(err),
    }
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
    reader: &mut V4StreamReader<R>,
) -> Result<Option<UdpPacketRef<'_>>>
where
    R: AsyncRead + Unpin,
{
    match reader.read_frame_payload().await {
        Ok(payload) => Ok(Some(parse_udp_response(payload)?)),
        Err(Error::ZeroChunk) => Ok(None),
        Err(err) => Err(err),
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

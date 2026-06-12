#[cfg(unix)]
use std::mem::{size_of, zeroed};
use std::net::SocketAddr;
#[cfg(unix)]
use std::net::{SocketAddrV4, SocketAddrV6};
use std::ops::Range;
#[cfg(unix)]
use std::os::fd::AsRawFd;

use bytes::BytesMut;
#[cfg(unix)]
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::protocol::header::COMMAND_UDP_FORWARD;
use crate::protocol::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
use crate::proxy::outbound::udp::ensure_full_datagram_sent;

const SOCKS_UDP_RSV_FRAG_LEN: usize = 3;
const SOCKS_UDP_ATYP_LEN: usize = 1;
const SOCKS_UDP_DOMAIN_LEN_LEN: usize = 1;
const SOCKS_UDP_PORT_LEN: usize = 2;
pub(crate) const MAX_SOCKS_UDP_HEADER: usize = SOCKS_UDP_RSV_FRAG_LEN
    + SOCKS_UDP_ATYP_LEN
    + SOCKS_UDP_DOMAIN_LEN_LEN
    + u8::MAX as usize
    + SOCKS_UDP_PORT_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocksUdpHeader {
    address: SocksUdpAddress,
    payload_start: usize,
    payload_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SocksUdpAddress {
    Domain(Range<usize>),
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnellUdpPacketKind {
    Request,
    Response,
}

impl SocksUdpHeader {
    pub(crate) const fn payload_len(&self) -> usize {
        self.payload_len
    }

    fn snell_prefix_len(&self, kind: SnellUdpPacketKind) -> usize {
        match (&self.address, kind) {
            (SocksUdpAddress::Domain(host), _) => 1 + 1 + (host.end - host.start) + 2,
            (SocksUdpAddress::Ipv4, SnellUdpPacketKind::Request) => 1 + 1 + 1 + 4 + 2,
            (SocksUdpAddress::Ipv4, SnellUdpPacketKind::Response) => 1 + 4 + 2,
            (SocksUdpAddress::Ipv6, SnellUdpPacketKind::Request) => 1 + 1 + 1 + 16 + 2,
            (SocksUdpAddress::Ipv6, SnellUdpPacketKind::Response) => 1 + 16 + 2,
        }
    }
}

pub(crate) async fn recv_socks_udp_datagram_into(
    socket: &UdpSocket,
    datagram: &mut BytesMut,
    max_datagram_len: usize,
) -> Result<(usize, SocketAddr)> {
    datagram.clear();

    let recv_buffer_len = max_datagram_len.saturating_add(1);
    if datagram.capacity() > recv_buffer_len.saturating_mul(2) {
        *datagram = BytesMut::with_capacity(recv_buffer_len);
    }

    datagram.reserve(recv_buffer_len);

    let (n, peer) = socket.recv_buf_from(datagram).await?;
    if socks_udp_datagram_too_large(n, max_datagram_len) {
        datagram.clear();
        return Err(Error::PayloadTooLarge);
    }

    Ok((n, peer))
}

pub(crate) const fn max_socks_udp_datagram_len(max_snell_udp_payload_len: usize) -> usize {
    max_snell_udp_payload_len + SOCKS_UDP_RSV_FRAG_LEN
}

fn socks_udp_datagram_too_large(n: usize, max_datagram_len: usize) -> bool {
    n > max_datagram_len
}

pub(crate) fn parse_socks_udp_header(datagram: &[u8]) -> Result<SocksUdpHeader> {
    if datagram.len() < 4 || datagram[..3] != [0, 0, 0] {
        return Err(Error::InvalidSocksRequest);
    }

    match datagram[3] {
        ATYP_IPV4 => {
            let payload_start = 3 + 1 + 4 + 2;
            if datagram.len() < payload_start {
                return Err(Error::InvalidSocksRequest);
            }
            Ok(SocksUdpHeader {
                address: SocksUdpAddress::Ipv4,
                payload_start,
                payload_len: datagram.len() - payload_start,
            })
        }
        ATYP_DOMAIN => {
            if datagram.len() < 5 {
                return Err(Error::InvalidSocksRequest);
            }
            let host_len = datagram[4] as usize;
            if host_len == 0 {
                return Err(Error::InvalidSocksRequest);
            }
            let host_start = 5;
            let host_end = host_start + host_len;
            let payload_start = host_end + 2;
            if datagram.len() < payload_start {
                return Err(Error::InvalidSocksRequest);
            }
            std::str::from_utf8(&datagram[host_start..host_end])?;
            Ok(SocksUdpHeader {
                address: SocksUdpAddress::Domain(host_start..host_end),
                payload_start,
                payload_len: datagram.len() - payload_start,
            })
        }
        ATYP_IPV6 => {
            let payload_start = 3 + 1 + 16 + 2;
            if datagram.len() < payload_start {
                return Err(Error::InvalidSocksRequest);
            }
            Ok(SocksUdpHeader {
                address: SocksUdpAddress::Ipv6,
                payload_start,
                payload_len: datagram.len() - payload_start,
            })
        }
        _ => Err(Error::InvalidSocksRequest),
    }
}

pub(crate) fn reframe_socks_udp_packet(
    datagram: &mut BytesMut,
    header: &SocksUdpHeader,
    kind: SnellUdpPacketKind,
    max_snell_udp_payload_len: usize,
) -> Result<usize> {
    if header.payload_start > datagram.len()
        || datagram.len() - header.payload_start != header.payload_len
    {
        return Err(Error::InvalidSocksRequest);
    }

    let prefix_len = header.snell_prefix_len(kind);
    let Some(packet_len) = prefix_len.checked_add(header.payload_len) else {
        return Err(Error::PayloadTooLarge);
    };

    if packet_len > max_snell_udp_payload_len {
        return Err(Error::PayloadTooLarge);
    }

    let Some(prefix_start) = header.payload_start.checked_sub(prefix_len) else {
        return Err(Error::InvalidSocksRequest);
    };

    match (&header.address, kind) {
        (SocksUdpAddress::Domain(host), SnellUdpPacketKind::Request) => {
            let host_bytes = datagram
                .get(host.clone())
                .ok_or(Error::InvalidSocksRequest)?;
            std::str::from_utf8(host_bytes)?;
            datagram[prefix_start] = COMMAND_UDP_FORWARD;
        }
        (SocksUdpAddress::Domain(host), SnellUdpPacketKind::Response) => {
            let host_bytes = datagram
                .get(host.clone())
                .ok_or(Error::InvalidSocksRequest)?;
            std::str::from_utf8(host_bytes)?;
            datagram[prefix_start] = ATYP_DOMAIN;
        }
        (SocksUdpAddress::Ipv4, SnellUdpPacketKind::Request) => {
            datagram[prefix_start] = COMMAND_UDP_FORWARD;
            datagram[prefix_start + 1] = 0;
            datagram[prefix_start + 2] = 0x04;
        }
        (SocksUdpAddress::Ipv4, SnellUdpPacketKind::Response) => {
            datagram[prefix_start] = 0x04;
        }
        (SocksUdpAddress::Ipv6, SnellUdpPacketKind::Request) => {
            datagram[prefix_start] = COMMAND_UDP_FORWARD;
            datagram[prefix_start + 1] = 0;
            datagram[prefix_start + 2] = 0x06;
        }
        (SocksUdpAddress::Ipv6, SnellUdpPacketKind::Response) => {
            datagram[prefix_start] = 0x06;
        }
    }

    Ok(prefix_start)
}

pub(crate) async fn send_udp_parts(
    socket: &UdpSocket,
    first: &[u8],
    second: &[u8],
    target: SocketAddr,
    max_len: usize,
    scratch: &mut BytesMut,
) -> Result<()> {
    scratch.clear();
    let expected = first
        .len()
        .checked_add(second.len())
        .ok_or(Error::PayloadTooLarge)?;
    if expected > max_len {
        return Err(Error::PayloadTooLarge);
    }

    send_udp_parts_checked(socket, first, second, target, expected, scratch).await
}

#[cfg(unix)]
async fn send_udp_parts_checked(
    socket: &UdpSocket,
    first: &[u8],
    second: &[u8],
    target: SocketAddr,
    expected: usize,
    _scratch: &mut BytesMut,
) -> Result<()> {
    let sent = socket
        .async_io(Interest::WRITABLE, || {
            try_send_udp_parts(socket, first, second, target)
        })
        .await?;

    ensure_full_datagram_sent(sent, expected)
}

#[cfg(not(unix))]
async fn send_udp_parts_checked(
    socket: &UdpSocket,
    first: &[u8],
    second: &[u8],
    target: SocketAddr,
    expected: usize,
    scratch: &mut BytesMut,
) -> Result<()> {
    scratch.reserve(expected);
    scratch.extend_from_slice(first);
    scratch.extend_from_slice(second);

    send_udp_packet(socket, &scratch[..], target).await
}

#[cfg(unix)]
fn try_send_udp_parts(
    socket: &UdpSocket,
    first: &[u8],
    second: &[u8],
    target: SocketAddr,
) -> std::io::Result<usize> {
    let (mut storage, storage_len) = socket_addr_storage(target);
    let mut iov = [
        libc::iovec {
            iov_base: first.as_ptr().cast_mut().cast(),
            iov_len: first.len(),
        },
        libc::iovec {
            iov_base: second.as_ptr().cast_mut().cast(),
            iov_len: second.len(),
        },
    ];

    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = (&mut storage as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = storage_len;
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len() as _;

    loop {
        let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_DONTWAIT) };
        if n >= 0 {
            return Ok(n as usize);
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }

        return Err(err);
    }
}

#[cfg(unix)]
fn socket_addr_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let storage_len = match addr {
        SocketAddr::V4(addr) => {
            let raw = sockaddr_in(addr);
            unsafe {
                (&mut storage as *mut libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in>()
                    .write(raw);
            }
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(addr) => {
            let raw = sockaddr_in6(addr);
            unsafe {
                (&mut storage as *mut libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in6>()
                    .write(raw);
            }
            size_of::<libc::sockaddr_in6>()
        }
    };

    (storage, storage_len as libc::socklen_t)
}

#[cfg(unix)]
fn sockaddr_in(addr: SocketAddrV4) -> libc::sockaddr_in {
    let mut raw: libc::sockaddr_in = unsafe { zeroed() };
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))]
    {
        raw.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    raw.sin_family = libc::AF_INET as libc::sa_family_t;
    raw.sin_port = addr.port().to_be();
    raw.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(addr.ip().octets()),
    };
    raw
}

#[cfg(unix)]
fn sockaddr_in6(addr: SocketAddrV6) -> libc::sockaddr_in6 {
    let mut raw: libc::sockaddr_in6 = unsafe { zeroed() };
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))]
    {
        raw.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
    }
    raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    raw.sin6_port = addr.port().to_be();
    raw.sin6_flowinfo = addr.flowinfo();
    raw.sin6_addr = libc::in6_addr {
        s6_addr: addr.ip().octets(),
    };
    raw.sin6_scope_id = addr.scope_id();
    raw
}

#[cfg(not(unix))]
async fn send_udp_packet(socket: &UdpSocket, packet: &[u8], target: SocketAddr) -> Result<()> {
    let sent = socket.send_to(packet, target).await?;
    ensure_full_datagram_sent(sent, packet.len())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use bytes::{Buf, BytesMut};
    use tokio::net::UdpSocket;

    use super as udp_io;
    use super::{
        SnellUdpPacketKind, parse_socks_udp_header, recv_socks_udp_datagram_into,
        reframe_socks_udp_packet,
    };
    use crate::error::Error;
    use crate::protocol::socks5::write_udp_packet as write_socks_udp_packet;
    use crate::protocol::udp::{
        AddressRef, parse_udp_request, parse_udp_response, write_udp_request_prefix,
        write_udp_response_prefix,
    };

    fn v4_socks_udp_datagram_limit() -> usize {
        udp_io::max_socks_udp_datagram_len(crate::MAX_PACKET_SIZE)
    }

    fn reframe(mut datagram: BytesMut, kind: SnellUdpPacketKind) -> (BytesMut, usize) {
        let header = parse_socks_udp_header(&datagram).unwrap();
        let payload_len = header.payload_len();
        let payload_ptr = unsafe { datagram.as_ptr().add(header.payload_start) };

        let prefix_start =
            reframe_socks_udp_packet(&mut datagram, &header, kind, crate::MAX_PACKET_SIZE).unwrap();
        datagram.advance(prefix_start);

        let new_payload_start = datagram.len() - payload_len;
        let new_payload_ptr = unsafe { datagram.as_ptr().add(new_payload_start) };
        assert_eq!(new_payload_ptr, payload_ptr);

        (datagram, payload_len)
    }

    #[test]
    fn reframes_ipv4_socks_udp_as_snell_request_without_payload_copy() {
        let payload = b"hello";
        let mut datagram = BytesMut::new();
        let address = AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        write_socks_udp_packet(&mut datagram, address, 53, payload).unwrap();

        let (reframed, payload_len) = reframe(datagram, SnellUdpPacketKind::Request);
        let parsed = parse_udp_request(&reframed).unwrap();

        assert_eq!(payload_len, payload.len());
        assert_eq!(parsed.address, address);
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn reframes_domain_socks_udp_as_snell_response_without_payload_copy() {
        let payload = b"dns-response";
        let mut datagram = BytesMut::new();
        let address = AddressRef::Domain("example.com");
        write_socks_udp_packet(&mut datagram, address, 5353, payload).unwrap();

        let (reframed, payload_len) = reframe(datagram, SnellUdpPacketKind::Response);
        let parsed = parse_udp_response(&reframed).unwrap();

        assert_eq!(payload_len, payload.len());
        assert_eq!(parsed.address, address);
        assert_eq!(parsed.port, 5353);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn reframe_matches_existing_snell_prefix_encoders() {
        let payload = b"payload";
        let mut datagram = BytesMut::new();
        let address = AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        write_socks_udp_packet(&mut datagram, address, 443, payload).unwrap();

        let (request, _) = reframe(datagram.clone(), SnellUdpPacketKind::Request);
        let mut expected_request = BytesMut::new();
        write_udp_request_prefix(&mut expected_request, address, 443).unwrap();
        expected_request.extend_from_slice(payload);
        assert_eq!(request, expected_request);

        let (response, _) = reframe(datagram, SnellUdpPacketKind::Response);
        let mut expected_response = BytesMut::new();
        write_udp_response_prefix(&mut expected_response, address, 443).unwrap();
        expected_response.extend_from_slice(payload);
        assert_eq!(response, expected_response);
    }

    #[test]
    fn rejects_reframed_payload_larger_than_snell_packet() {
        let mut datagram = BytesMut::new();
        let address = AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let payload = vec![0x42; crate::MAX_PACKET_SIZE];
        write_socks_udp_packet(&mut datagram, address, 53, &payload).unwrap();
        let header = parse_socks_udp_header(&datagram).unwrap();

        assert!(matches!(
            reframe_socks_udp_packet(
                &mut datagram,
                &header,
                SnellUdpPacketKind::Request,
                crate::MAX_PACKET_SIZE,
            ),
            Err(Error::PayloadTooLarge)
        ));
    }

    #[test]
    fn reframe_allows_large_packet_when_snell_record_limit_allows_it() {
        let mut datagram = BytesMut::new();
        let address = AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let payload = vec![0x42; 60_000];
        write_socks_udp_packet(&mut datagram, address, 53, &payload).unwrap();
        let header = parse_socks_udp_header(&datagram).unwrap();

        let prefix_start = reframe_socks_udp_packet(
            &mut datagram,
            &header,
            SnellUdpPacketKind::Request,
            crate::MAX_V6_RECORD_PAYLOAD_LEN,
        )
        .unwrap();
        datagram.advance(prefix_start);
        let parsed = parse_udp_request(&datagram).unwrap();

        assert_eq!(parsed.address, address);
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn rejects_stale_socks_udp_header_without_panicking() {
        let mut datagram = BytesMut::new();
        write_socks_udp_packet(
            &mut datagram,
            AddressRef::Domain("example.com"),
            53,
            b"payload",
        )
        .unwrap();
        let header = parse_socks_udp_header(&datagram).unwrap();
        datagram.truncate(header.payload_start);

        assert!(matches!(
            reframe_socks_udp_packet(
                &mut datagram,
                &header,
                SnellUdpPacketKind::Request,
                crate::MAX_PACKET_SIZE,
            ),
            Err(Error::InvalidSocksRequest)
        ));
    }

    #[test]
    fn max_socks_udp_header_includes_domain_length_byte() {
        let host = "x".repeat(u8::MAX as usize);
        let mut datagram = BytesMut::new();
        write_socks_udp_packet(&mut datagram, AddressRef::Domain(&host), 53, &[]).unwrap();

        assert_eq!(datagram.len(), udp_io::MAX_SOCKS_UDP_HEADER);
    }

    #[tokio::test]
    async fn recv_socks_udp_datagram_reports_peer_and_preserves_bytes() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let mut sent = BytesMut::new();
        write_socks_udp_packet(
            &mut sent,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"query",
        )
        .unwrap();

        sender
            .send_to(&sent, receiver.local_addr().unwrap())
            .await
            .unwrap();

        let mut received = BytesMut::new();
        let (n, peer) =
            recv_socks_udp_datagram_into(&receiver, &mut received, v4_socks_udp_datagram_limit())
                .await
                .unwrap();

        assert_eq!(peer, sender_addr);
        assert_eq!(n, sent.len());
        assert_eq!(&received[..n], &sent[..]);
    }

    #[test]
    fn recv_oversized_sentinel_marks_datagram_too_large() {
        let v4_limit = v4_socks_udp_datagram_limit();
        assert!(!udp_io::socks_udp_datagram_too_large(v4_limit, v4_limit,));
        assert!(udp_io::socks_udp_datagram_too_large(v4_limit + 1, v4_limit,));
    }

    #[test]
    fn socks_udp_datagram_limit_allows_socks_rsv_overhead() {
        assert_eq!(
            udp_io::max_socks_udp_datagram_len(crate::MAX_V6_RECORD_PAYLOAD_LEN),
            crate::MAX_V6_RECORD_PAYLOAD_LEN + 3
        );
    }

    #[tokio::test]
    async fn send_udp_parts_combines_prefix_and_payload() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut scratch = BytesMut::new();

        udp_io::send_udp_parts(
            &sender,
            b"header",
            b"payload",
            receiver.local_addr().unwrap(),
            v4_socks_udp_datagram_limit(),
            &mut scratch,
        )
        .await
        .unwrap();

        #[cfg(unix)]
        {
            assert!(scratch.is_empty());
            assert_eq!(scratch.capacity(), 0);
        }

        let mut received = [0; 64];
        let (n, peer) = receiver.recv_from(&mut received).await.unwrap();

        assert_eq!(peer, sender.local_addr().unwrap());
        assert_eq!(&received[..n], b"headerpayload");
    }

    #[tokio::test]
    async fn send_udp_parts_rejects_packets_above_call_site_limit() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut scratch = BytesMut::with_capacity(8);
        scratch.extend_from_slice(b"stale");

        assert!(matches!(
            udp_io::send_udp_parts(
                &sender,
                b"header",
                b"payload",
                receiver.local_addr().unwrap(),
                b"header".len() + b"payload".len() - 1,
                &mut scratch,
            )
            .await,
            Err(Error::PayloadTooLarge)
        ));
        assert_eq!(scratch.capacity(), 8);
        assert!(scratch.is_empty());
    }
}

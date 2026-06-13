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

pub(crate) async fn recv_udp_datagram_into(
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
    if udp_datagram_too_large(n, max_datagram_len) {
        datagram.clear();
        return Err(Error::PayloadTooLarge);
    }

    Ok((n, peer))
}

pub(crate) async fn recv_socks_udp_datagram_into(
    socket: &UdpSocket,
    datagram: &mut BytesMut,
    max_datagram_len: usize,
) -> Result<(usize, SocketAddr)> {
    recv_udp_datagram_into(socket, datagram, max_datagram_len).await
}

pub(crate) const fn max_socks_udp_datagram_len(max_snell_udp_payload_len: usize) -> usize {
    max_snell_udp_payload_len + SOCKS_UDP_RSV_FRAG_LEN
}

fn udp_datagram_too_large(n: usize, max_datagram_len: usize) -> bool {
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

    // SAFETY: zero is a valid baseline for msghdr; the fields used by sendmsg
    // are filled immediately below before the value is passed to libc.
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = (&mut storage as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = storage_len;
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len() as _;

    loop {
        // SAFETY: msg points to stack-owned sockaddr/iovec values that live for
        // this call, and the iovec buffers are valid immutable byte slices.
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
    // SAFETY: zeroed sockaddr_storage is valid storage; each match arm writes a
    // concrete sockaddr value before the storage is read by sendmsg.
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let storage_len = match addr {
        SocketAddr::V4(addr) => {
            let raw = sockaddr_in(addr);
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in by the platform ABI.
            unsafe {
                (&mut storage as *mut libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in>()
                    .write(raw);
            }
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(addr) => {
            let raw = sockaddr_in6(addr);
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in6 by the platform ABI.
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
    // SAFETY: zeroed sockaddr_in is a valid baseline; all required fields are
    // assigned before the value is passed to libc.
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
    // SAFETY: zeroed sockaddr_in6 is a valid baseline; all required fields are
    // assigned before the value is passed to libc.
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
mod tests;

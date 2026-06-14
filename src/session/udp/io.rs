#[cfg(target_os = "linux")]
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::net::{SocketAddrV4, SocketAddrV6};
use std::ops::Range;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use bytes::{BufMut, BytesMut};
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::protocol::header::COMMAND_UDP_FORWARD;
use crate::protocol::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
use crate::protocol::udp::AddressRef;

pub(crate) const UDP_BATCH_SIZE: usize = 20;
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

pub(crate) struct UdpRecvBatch {
    slots: Vec<UdpRecvSlot>,
    count: usize,
    headroom: usize,
    max_datagram_len: usize,
    payload_limit: usize,
}

struct UdpRecvSlot {
    datagram: BytesMut,
    payload_len: usize,
    peer: Option<SocketAddr>,
    oversized: bool,
}

pub(crate) struct UdpRecvDatagram<'a> {
    slot: &'a UdpRecvSlot,
    headroom: usize,
}

pub(crate) struct UdpRecvDatagramMut<'a> {
    slot: &'a mut UdpRecvSlot,
    headroom: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct UdpSendPacket<'a> {
    first: &'a [u8],
    second: &'a [u8],
    target: SocketAddr,
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

    pub(crate) fn target<'a>(&self, datagram: &'a [u8]) -> Result<(AddressRef<'a>, u16)> {
        if self.payload_start > datagram.len()
            || datagram.len() - self.payload_start != self.payload_len
        {
            return Err(Error::InvalidSocksRequest);
        }

        let (address, port_start) = match &self.address {
            SocksUdpAddress::Domain(host) => {
                let host_bytes = datagram
                    .get(host.clone())
                    .ok_or(Error::InvalidSocksRequest)?;
                (
                    AddressRef::Domain(std::str::from_utf8(host_bytes)?),
                    host.end,
                )
            }
            SocksUdpAddress::Ipv4 => {
                let octets = datagram.get(4..8).ok_or(Error::InvalidSocksRequest)?;
                (
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(
                        octets[0], octets[1], octets[2], octets[3],
                    ))),
                    8,
                )
            }
            SocksUdpAddress::Ipv6 => {
                let octets = datagram.get(4..20).ok_or(Error::InvalidSocksRequest)?;
                (
                    AddressRef::Ip(IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(octets).map_err(|_| Error::InvalidSocksRequest)?,
                    ))),
                    20,
                )
            }
        };
        let port = read_socks_udp_port(datagram, port_start)?;
        Ok((address, port))
    }

    const fn snell_prefix_len(&self, kind: SnellUdpPacketKind) -> usize {
        match (&self.address, kind) {
            (SocksUdpAddress::Domain(host), _) => 1 + 1 + (host.end - host.start) + 2,
            (SocksUdpAddress::Ipv4, SnellUdpPacketKind::Request) => 1 + 1 + 1 + 4 + 2,
            (SocksUdpAddress::Ipv4, SnellUdpPacketKind::Response) => 1 + 4 + 2,
            (SocksUdpAddress::Ipv6, SnellUdpPacketKind::Request) => 1 + 1 + 1 + 16 + 2,
            (SocksUdpAddress::Ipv6, SnellUdpPacketKind::Response) => 1 + 16 + 2,
        }
    }
}

fn read_socks_udp_port(datagram: &[u8], start: usize) -> Result<u16> {
    let bytes = datagram
        .get(start..start + SOCKS_UDP_PORT_LEN)
        .ok_or(Error::InvalidSocksRequest)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

impl UdpRecvBatch {
    pub(crate) fn new(max_datagram_len: usize) -> Self {
        Self::with_capacity(max_datagram_len, UDP_BATCH_SIZE)
    }

    pub(crate) fn with_capacity(max_datagram_len: usize, batch_size: usize) -> Self {
        let batch_size = batch_size.clamp(1, UDP_BATCH_SIZE);
        let recv_buffer_len = max_datagram_len.saturating_add(1);
        Self {
            slots: (0..batch_size)
                .map(|_| UdpRecvSlot {
                    datagram: BytesMut::with_capacity(recv_buffer_len),
                    payload_len: 0,
                    peer: None,
                    oversized: false,
                })
                .collect(),
            count: 0,
            headroom: 0,
            max_datagram_len,
            payload_limit: max_datagram_len,
        }
    }

    pub(crate) async fn recv_from(&mut self, socket: &UdpSocket) -> Result<usize> {
        self.recv_from_with_headroom(socket, 0, self.max_datagram_len)
            .await
    }

    pub(crate) async fn recv_from_with_headroom(
        &mut self,
        socket: &UdpSocket,
        headroom: usize,
        payload_limit: usize,
    ) -> Result<usize> {
        self.prepare_slots(headroom, payload_limit)?;
        let count = recv_udp_batch_platform(socket, self).await?;
        self.count = count;
        Ok(count)
    }

    pub(crate) fn get(&self, index: usize) -> Option<UdpRecvDatagram<'_>> {
        (index < self.count).then(|| UdpRecvDatagram {
            slot: &self.slots[index],
            headroom: self.headroom,
        })
    }

    pub(crate) fn get_mut(&mut self, index: usize) -> Option<UdpRecvDatagramMut<'_>> {
        (index < self.count).then(|| UdpRecvDatagramMut {
            slot: &mut self.slots[index],
            headroom: self.headroom,
        })
    }

    fn prepare_slots(&mut self, headroom: usize, payload_limit: usize) -> Result<()> {
        let recv_buffer_len = payload_limit.saturating_add(1);
        let total_len = headroom
            .checked_add(recv_buffer_len)
            .ok_or(Error::PayloadTooLarge)?;
        self.count = 0;
        self.headroom = headroom;
        self.payload_limit = payload_limit;
        for slot in &mut self.slots {
            slot.datagram.clear();
            slot.payload_len = 0;
            slot.peer = None;
            slot.oversized = false;
            if slot.datagram.capacity() > total_len.saturating_mul(2) {
                slot.datagram = BytesMut::with_capacity(total_len);
            }
            slot.datagram.reserve(total_len);
            slot.datagram.resize(headroom, 0);
            let spare_len = slot.datagram.chunk_mut().len();
            if spare_len < recv_buffer_len {
                slot.datagram.reserve(recv_buffer_len - spare_len);
            }
        }
        Ok(())
    }
}

impl UdpRecvSlot {
    const fn set_received(&mut self, payload_len: usize, peer: SocketAddr, payload_limit: usize) {
        self.payload_len = payload_len;
        self.peer = Some(peer);
        self.oversized = udp_datagram_too_large(payload_len, payload_limit);
    }
}

impl<'a> UdpRecvDatagram<'a> {
    pub(crate) const fn peer(&self) -> SocketAddr {
        self.slot.peer.expect("received UDP slot has peer")
    }

    pub(crate) const fn payload_len(&self) -> usize {
        self.slot.payload_len
    }

    pub(crate) const fn is_oversized(&self) -> bool {
        self.slot.oversized
    }

    pub(crate) fn datagram(&self) -> &'a [u8] {
        &self.slot.datagram[..self.headroom + self.slot.payload_len]
    }

    pub(crate) fn payload(&self) -> &'a [u8] {
        &self.slot.datagram[self.headroom..self.headroom + self.slot.payload_len]
    }
}

impl UdpRecvDatagramMut<'_> {
    pub(crate) const fn datagram_mut(&mut self) -> &mut BytesMut {
        &mut self.slot.datagram
    }

    pub(crate) fn payload_mut(&mut self) -> &mut [u8] {
        let start = self.headroom;
        let end = start + self.slot.payload_len;
        &mut self.slot.datagram[start..end]
    }
}

impl<'a> UdpSendPacket<'a> {
    pub(crate) const fn single(payload: &'a [u8], target: SocketAddr) -> Self {
        Self {
            first: payload,
            second: &[],
            target,
        }
    }

    pub(crate) const fn parts(first: &'a [u8], second: &'a [u8], target: SocketAddr) -> Self {
        Self {
            first,
            second,
            target,
        }
    }

    fn len(self) -> Result<usize> {
        self.first
            .len()
            .checked_add(self.second.len())
            .ok_or(Error::PayloadTooLarge)
    }
}

pub(crate) async fn send_udp_batch(
    socket: &UdpSocket,
    packets: &[UdpSendPacket<'_>],
    max_len: usize,
) -> Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    for packet in packets {
        if packet.len()? > max_len {
            return Err(Error::PayloadTooLarge);
        }
    }
    send_udp_batch_platform(socket, packets).await?;
    Ok(packets.len())
}

pub(crate) const fn max_socks_udp_datagram_len(max_snell_udp_payload_len: usize) -> usize {
    max_snell_udp_payload_len + SOCKS_UDP_RSV_FRAG_LEN
}

const fn ensure_full_datagram_sent(sent: usize, expected: usize) -> Result<()> {
    if sent == expected {
        return Ok(());
    }

    Err(Error::ShortUdpWrite { sent, expected })
}

const fn udp_datagram_too_large(n: usize, max_datagram_len: usize) -> bool {
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

#[cfg(target_os = "linux")]
async fn recv_udp_batch_platform(socket: &UdpSocket, batch: &mut UdpRecvBatch) -> Result<usize> {
    Ok(socket
        .async_io(Interest::READABLE, || try_recvmmsg(socket, batch))
        .await?)
}

#[cfg(not(target_os = "linux"))]
async fn recv_udp_batch_platform(socket: &UdpSocket, batch: &mut UdpRecvBatch) -> Result<usize> {
    let slot = &mut batch.slots[0];
    let (payload_len, peer) = socket.recv_buf_from(&mut slot.datagram).await?;
    slot.set_received(payload_len, peer, batch.payload_limit);
    Ok(1)
}

#[cfg(target_os = "linux")]
fn try_recvmmsg(socket: &UdpSocket, batch: &mut UdpRecvBatch) -> std::io::Result<usize> {
    let count = batch.slots.len();
    let recv_buffer_len = batch.payload_limit.saturating_add(1);
    let mut storages =
        std::array::from_fn::<libc::sockaddr_storage, UDP_BATCH_SIZE, _>(|_| unsafe { zeroed() });
    let mut iovecs = std::array::from_fn::<libc::iovec, UDP_BATCH_SIZE, _>(|_| unsafe { zeroed() });
    let mut msgs = std::array::from_fn::<libc::mmsghdr, UDP_BATCH_SIZE, _>(|_| unsafe { zeroed() });

    for i in 0..count {
        let spare = batch.slots[i].datagram.chunk_mut();
        iovecs[i].iov_base = spare.as_mut_ptr().cast();
        iovecs[i].iov_len = recv_buffer_len;
        msgs[i].msg_hdr.msg_name = (&mut storages[i] as *mut libc::sockaddr_storage).cast();
        msgs[i].msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msgs[i].msg_hdr.msg_iov = (&mut iovecs[i] as *mut libc::iovec).cast();
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    loop {
        // SAFETY: `msgs` points to stack-owned mmsghdr values whose iovec and
        // sockaddr buffers remain alive for the syscall; slot spare capacity is
        // reserved before the pointers are built.
        let n = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                msgs.as_mut_ptr(),
                count as _,
                0,
                std::ptr::null_mut(),
            )
        };
        if n >= 0 {
            let count = n as usize;
            for i in 0..count {
                let payload_len = msgs[i].msg_len as usize;
                // SAFETY: recvmmsg wrote exactly `payload_len` bytes into the
                // spare capacity advertised by the iovec for this slot.
                unsafe {
                    batch.slots[i].datagram.advance_mut(payload_len);
                }
                let peer = socket_addr_from_storage(&storages[i], msgs[i].msg_hdr.msg_namelen)?;
                batch.slots[i].set_received(payload_len, peer, batch.payload_limit);
            }
            return Ok(count);
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(target_os = "linux")]
async fn send_udp_batch_platform(socket: &UdpSocket, packets: &[UdpSendPacket<'_>]) -> Result<()> {
    let mut sent = 0;
    while sent < packets.len() {
        let end = (sent + UDP_BATCH_SIZE).min(packets.len());
        let result = socket
            .async_io(Interest::WRITABLE, || {
                try_sendmmsg(socket, &packets[sent..end])
            })
            .await?;
        if let Some((short_sent, expected)) = result.short_write {
            ensure_full_datagram_sent(short_sent, expected)?;
        }
        if result.sent == 0 {
            let expected = packets[sent].len()?;
            return Err(Error::ShortUdpWrite { sent: 0, expected });
        }
        sent += result.sent;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn send_udp_batch_platform(socket: &UdpSocket, packets: &[UdpSendPacket<'_>]) -> Result<()> {
    let mut scratch = BytesMut::new();
    for packet in packets {
        let expected = packet.len()?;
        scratch.clear();
        scratch.reserve(expected);
        scratch.extend_from_slice(packet.first);
        scratch.extend_from_slice(packet.second);
        let sent = socket.send_to(&scratch, packet.target).await?;
        ensure_full_datagram_sent(sent, expected)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct RawSendBatchResult {
    sent: usize,
    short_write: Option<(usize, usize)>,
}

#[cfg(target_os = "linux")]
fn try_sendmmsg(
    socket: &UdpSocket,
    packets: &[UdpSendPacket<'_>],
) -> std::io::Result<RawSendBatchResult> {
    let count = packets.len().min(UDP_BATCH_SIZE);
    let mut storages =
        std::array::from_fn::<libc::sockaddr_storage, UDP_BATCH_SIZE, _>(|_| unsafe { zeroed() });
    let mut storage_lens = [0 as libc::socklen_t; UDP_BATCH_SIZE];
    let mut iovecs =
        std::array::from_fn::<[libc::iovec; 2], UDP_BATCH_SIZE, _>(|_| unsafe { zeroed() });
    let mut msgs = std::array::from_fn::<libc::mmsghdr, UDP_BATCH_SIZE, _>(|_| unsafe { zeroed() });

    for i in 0..count {
        let (storage, storage_len) = socket_addr_storage(packets[i].target);
        storages[i] = storage;
        storage_lens[i] = storage_len;
        iovecs[i][0] = libc::iovec {
            iov_base: packets[i].first.as_ptr().cast_mut().cast(),
            iov_len: packets[i].first.len(),
        };
        iovecs[i][1] = libc::iovec {
            iov_base: packets[i].second.as_ptr().cast_mut().cast(),
            iov_len: packets[i].second.len(),
        };
        msgs[i].msg_hdr.msg_name = (&mut storages[i] as *mut libc::sockaddr_storage).cast();
        msgs[i].msg_hdr.msg_namelen = storage_lens[i];
        msgs[i].msg_hdr.msg_iov = iovecs[i].as_mut_ptr();
        // When the second segment is empty, advertise a single iovec so the
        // kernel skips processing a zero-length entry per datagram.
        msgs[i].msg_hdr.msg_iovlen = if packets[i].second.is_empty() { 1 } else { 2 };
    }

    loop {
        // SAFETY: `msgs` points to stack-owned mmsghdr values whose sockaddr
        // and iovec buffers remain alive for the syscall. The iovec byte slices
        // are borrowed from the caller and live for this call.
        let n = unsafe { libc::sendmmsg(socket.as_raw_fd(), msgs.as_mut_ptr(), count as _, 0) };
        if n >= 0 {
            let sent = n as usize;
            let short_write = (0..sent).find_map(|i| {
                let expected = packets[i].len().ok()?;
                (msgs[i].msg_len as usize != expected)
                    .then_some((msgs[i].msg_len as usize, expected))
            });
            return Ok(RawSendBatchResult { sent, short_write });
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn socket_addr_from_storage(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> std::io::Result<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: The kernel wrote an AF_INET sockaddr into this storage.
            let raw = unsafe { *(storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(raw.sin_port),
            ))
        }
        libc::AF_INET6 if len as usize >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: The kernel wrote an AF_INET6 sockaddr into this storage.
            let raw = unsafe { *(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(raw.sin6_addr.s6_addr)),
                u16::from_be(raw.sin6_port),
            ))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected UDP peer address family",
        )),
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(test)]
mod tests;

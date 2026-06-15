use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::task::{Context, Poll, ready};

use bytes::{BufMut, Bytes, BytesMut};
use rustix::net::{RecvFlags, SendFlags, SocketAddrAny};
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

pub(crate) struct UdpSendBatch {
    packets: Vec<OwnedUdpSendPacket>,
    max_len: usize,
    sent: usize,
    scratch: BytesMut,
    scratch_index: Option<usize>,
}

struct OwnedUdpSendPacket {
    first: Bytes,
    second: Bytes,
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

    pub(crate) fn poll_recv_from(
        &mut self,
        socket: &UdpSocket,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize>> {
        self.poll_recv_from_with_headroom(socket, 0, self.max_datagram_len, cx)
    }

    pub(crate) fn poll_recv_from_with_headroom(
        &mut self,
        socket: &UdpSocket,
        headroom: usize,
        payload_limit: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize>> {
        self.prepare_slots(headroom, payload_limit)?;
        let count = ready!(poll_recv_udp_batch_platform(socket, self, cx))?;
        self.count = count;
        Poll::Ready(Ok(count))
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

impl UdpSendBatch {
    pub(crate) fn single(payload: Bytes, target: SocketAddr, max_len: usize) -> Self {
        Self::new(
            vec![OwnedUdpSendPacket {
                first: payload,
                second: Bytes::new(),
                target,
            }],
            max_len,
        )
    }

    pub(crate) fn parts(first: Bytes, second: Bytes, target: SocketAddr, max_len: usize) -> Self {
        Self::new(
            vec![OwnedUdpSendPacket {
                first,
                second,
                target,
            }],
            max_len,
        )
    }

    fn new(packets: Vec<OwnedUdpSendPacket>, max_len: usize) -> Self {
        Self {
            packets,
            max_len,
            sent: 0,
            scratch: BytesMut::new(),
            scratch_index: None,
        }
    }

    pub(crate) fn poll_send(
        &mut self,
        socket: &UdpSocket,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize>> {
        while self.sent < self.packets.len() {
            let packet = &self.packets[self.sent];
            let expected = packet.len()?;
            if expected > self.max_len {
                return Poll::Ready(Err(Error::PayloadTooLarge));
            }
            if self.scratch_index != Some(self.sent) {
                self.scratch.clear();
                self.scratch.reserve(expected);
                self.scratch.extend_from_slice(&packet.first);
                self.scratch.extend_from_slice(&packet.second);
                self.scratch_index = Some(self.sent);
            }
            let sent = loop {
                ready!(socket.poll_send_ready(cx))?;
                match socket.try_io(Interest::WRITABLE, || {
                    try_send_udp_datagram(socket, &self.scratch, packet.target)
                }) {
                    Ok(sent) => break sent,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => return Poll::Ready(Err(err.into())),
                }
            };
            ensure_full_datagram_sent(sent, expected)?;
            self.sent += 1;
            self.scratch_index = None;
        }
        Poll::Ready(Ok(self.sent))
    }
}

impl OwnedUdpSendPacket {
    fn len(&self) -> Result<usize> {
        self.first
            .len()
            .checked_add(self.second.len())
            .ok_or(Error::PayloadTooLarge)
    }
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

fn poll_recv_udp_batch_platform(
    socket: &UdpSocket,
    batch: &mut UdpRecvBatch,
    cx: &mut Context<'_>,
) -> Poll<Result<usize>> {
    loop {
        ready!(socket.poll_recv_ready(cx))?;
        match socket.try_io(Interest::READABLE, || try_recv_udp_batch(socket, batch)) {
            Ok(count) => return Poll::Ready(Ok(count)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Poll::Ready(Err(err.into())),
        }
    }
}

fn try_recv_udp_batch(socket: &UdpSocket, batch: &mut UdpRecvBatch) -> std::io::Result<usize> {
    let mut count = 0;
    while count < batch.slots.len() {
        match try_recv_udp_datagram(socket, &mut batch.slots[count], batch.payload_limit) {
            Ok(()) => count += 1,
            Err(err) if err == rustix::io::Errno::AGAIN || err == rustix::io::Errno::WOULDBLOCK => {
                if count == 0 {
                    return Err(errno_into_io(err));
                }
                break;
            }
            Err(err) => return Err(errno_into_io(err)),
        }
    }
    Ok(count)
}

fn try_recv_udp_datagram(
    socket: &UdpSocket,
    slot: &mut UdpRecvSlot,
    payload_limit: usize,
) -> rustix::io::Result<()> {
    loop {
        let result = {
            // SAFETY: `prepare_slots` reserves spare capacity large enough for
            // the datagram payload limit. rustix reports the initialized range.
            let spare = unsafe { slot.datagram.chunk_mut().as_uninit_slice_mut() };
            rustix::net::recvfrom(socket, spare, RecvFlags::empty())
        };
        match result {
            Ok(((initialized, _), recv_len, Some(peer))) => {
                let payload_len = initialized.len();
                // SAFETY: rustix initialized exactly `payload_len` bytes in the
                // spare capacity exposed above.
                unsafe {
                    slot.datagram.advance_mut(payload_len);
                }
                let peer = SocketAddr::try_from(peer)?;
                slot.set_received(recv_len, peer, payload_limit);
                return Ok(());
            }
            Ok(((_, _), _, None)) => return Err(rustix::io::Errno::INVAL),
            Err(rustix::io::Errno::INTR) => {}
            Err(err) => return Err(err),
        }
    }
}

fn try_send_udp_datagram(
    socket: &UdpSocket,
    payload: &[u8],
    target: SocketAddr,
) -> std::io::Result<usize> {
    rustix::io::retry_on_intr(|| {
        rustix::net::sendto(
            socket,
            payload,
            SendFlags::empty(),
            &SocketAddrAny::from(target),
        )
    })
    .map_err(errno_into_io)
}

fn errno_into_io(err: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(err.raw_os_error())
}

#[cfg(test)]
mod tests;

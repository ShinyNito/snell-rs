use std::mem::size_of;
use std::net::{IpAddr, SocketAddr};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::address::{Address, AddressRef, ip_port, split_host_port, validate_domain};
use crate::error::dst_prefix;
use crate::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_ERROR,
    COMMAND_TUNNEL, COMMAND_UDP, COMMAND_UDP_FORWARD, ERROR_REJECT, Error, PROTOCOL_VERSION,
    ParseState, Result, UDP_REQUEST_IP_LEN,
};

/// First three bytes of CONNECT / UDP setup: `VERSION CMD CLIENT_ID_LEN`.
///
/// Host/payload bytes after this prefix are variable-length and stay slice-based.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C, packed)]
struct WireControlHead {
    version: u8,
    command: u8,
    client_id_len: u8,
}

/// CONNECT prefix when `CLIENT_ID_LEN` is 0 (this project's encode path).
///
/// Layout: `VERSION CMD CLIENT_ID_LEN HOST_LEN`. UDP setup has no `HOST_LEN`.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C, packed)]
pub struct WireControlPrefix {
    pub version: u8,
    pub command: u8,
    pub client_id_len: u8,
    pub host_len: u8,
}

const _: () = assert!(size_of::<WireControlHead>() == 3);
const _: () = assert!(size_of::<WireControlPrefix>() == 4);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    pub destination: Address,
    pub reuse: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPacket<'a> {
    pub address: AddressRef<'a>,
    pub payload: &'a [u8],
    pub header_len: usize,
}

pub fn connect_request_len(destination: AddressRef<'_>) -> Result<usize> {
    connect_len(destination.host().len())
}

fn connect_len(host_len: usize) -> Result<usize> {
    if host_len == 0 || host_len > usize::from(u8::MAX) {
        return Err(Error::HostTooLong);
    }
    Ok(size_of::<WireControlPrefix>() + host_len + 2)
}

pub fn encode_connect_request(
    dst: &mut [u8],
    destination: AddressRef<'_>,
    reuse: bool,
) -> Result<usize> {
    let host = destination.host();
    let needed = connect_len(host.len())?;
    let wire = WireControlPrefix {
        version: PROTOCOL_VERSION,
        command: if reuse {
            COMMAND_CONNECT_V2
        } else {
            COMMAND_CONNECT
        },
        client_id_len: 0,
        host_len: host.len() as u8,
    };
    let (head, rest) = dst_prefix(dst, needed)?.split_at_mut(size_of::<WireControlPrefix>());
    head.copy_from_slice(wire.as_bytes());
    let (host_dst, port_dst) = rest.split_at_mut(host.len());
    host_dst.copy_from_slice(host.as_bytes());
    port_dst.copy_from_slice(&destination.port().to_be_bytes());
    Ok(needed)
}

pub fn decode_connect_request(src: &[u8]) -> Result<ConnectRequest> {
    let (request, consumed) = decode_connect_request_prefix(src)?;
    if src.len() != consumed {
        return Err(Error::Malformed("trailing bytes"));
    }
    Ok(request)
}

pub fn decode_connect_request_prefix(src: &[u8]) -> Result<(ConnectRequest, usize)> {
    let (head, after) = WireControlHead::ref_from_prefix(src).map_err(|_| Error::Truncated)?;
    if head.version != PROTOCOL_VERSION {
        return Err(Error::InvalidVersion(head.version));
    }
    let reuse = match head.command {
        COMMAND_CONNECT => false,
        COMMAND_CONNECT_V2 => true,
        other => return Err(Error::UnknownCommand(other)),
    };
    let client_id_len = usize::from(head.client_id_len);
    let host_port = after.get(client_id_len..).ok_or(Error::Truncated)?;
    match host_port.first() {
        None => return Err(Error::Truncated),
        Some(0) => return Err(Error::EmptyHost),
        Some(_) => {}
    }
    let (host, port, host_port_len) = split_host_port(host_port)?;
    let destination = match host.parse::<IpAddr>() {
        Ok(ip) => Address::Ip(SocketAddr::new(ip, port)),
        Err(_) => Address::domain(host, port)?,
    };
    Ok((
        ConnectRequest { destination, reuse },
        size_of::<WireControlHead>() + client_id_len + host_port_len,
    ))
}

pub fn encode_udp_setup(dst: &mut [u8]) -> Result<usize> {
    let wire = WireControlHead {
        version: PROTOCOL_VERSION,
        command: COMMAND_UDP,
        client_id_len: 0,
    };
    dst_prefix(dst, size_of::<WireControlHead>())?.copy_from_slice(wire.as_bytes());
    Ok(size_of::<WireControlHead>())
}

pub fn decode_udp_setup_prefix(src: &[u8]) -> Result<usize> {
    let (wire, after) = WireControlHead::ref_from_prefix(src).map_err(|_| Error::Truncated)?;
    if wire.version != PROTOCOL_VERSION {
        return Err(Error::InvalidVersion(wire.version));
    }
    if wire.command != COMMAND_UDP {
        return Err(Error::UnknownCommand(wire.command));
    }
    let client_id_len = usize::from(wire.client_id_len);
    if after.len() < client_id_len {
        return Err(Error::Truncated);
    }
    Ok(size_of::<WireControlHead>() + client_id_len)
}

pub fn encode_tunnel_reply(dst: &mut [u8]) -> Result<usize> {
    dst_prefix(dst, 1)?[0] = COMMAND_TUNNEL;
    Ok(1)
}

/// Server error reply with [`ERROR_REJECT`]; the message is cut to 255 bytes.
pub fn encode_reject(dst: &mut [u8], message: &str) -> Result<usize> {
    let msg = &message.as_bytes()[..message.len().min(usize::from(u8::MAX))];
    let needed = 3 + msg.len();
    let (head, tail) = dst_prefix(dst, needed)?.split_at_mut(3);
    head.copy_from_slice(&[COMMAND_ERROR, ERROR_REJECT, msg.len() as u8]);
    tail.copy_from_slice(msg);
    Ok(needed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerReply<'a> {
    Tunnel,
    Error { code: u8, message: &'a [u8] },
}

pub fn decode_server_reply(src: &[u8]) -> Result<ParseState<(ServerReply<'_>, usize)>> {
    match *src {
        [] => Ok(ParseState::Need(1)),
        [COMMAND_TUNNEL, ..] => Ok(ParseState::Done((ServerReply::Tunnel, 1))),
        [COMMAND_ERROR, code, msg_len, ref rest @ ..] => {
            let needed = 3 + usize::from(msg_len);
            match rest.get(..usize::from(msg_len)) {
                Some(message) => Ok(ParseState::Done((
                    ServerReply::Error { code, message },
                    needed,
                ))),
                None => Ok(ParseState::Need(needed)),
            }
        }
        [COMMAND_ERROR, ..] => Ok(ParseState::Need(3)),
        [other, ..] => Err(Error::UnknownCommand(other)),
    }
}

// UDP datagram headers share one address tail:
// IP     `ATYP(1) ADDR(4|16) PORT(2)`
// domain `LEN(1)  HOST(LEN)  PORT(2)`
//
// Request  `COMMAND_UDP_FORWARD`, then `UDP_REQUEST_IP_LEN` before an IP tail.
// Response `ATYP_DOMAIN` before a domain tail; an IP tail stands alone.

pub fn encode_udp_request(
    dst: &mut [u8],
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<usize> {
    let header_len = udp_request_header_len(address)?;
    let marker: &[u8] = match address {
        AddressRef::Ip(_) => &[COMMAND_UDP_FORWARD, UDP_REQUEST_IP_LEN],
        AddressRef::Domain { .. } => &[COMMAND_UDP_FORWARD],
    };
    encode_udp_datagram(dst, header_len, marker, address, payload)
}

pub fn decode_udp_request(src: &[u8]) -> Result<UdpPacket<'_>> {
    let [command, host_len, ..] = *src else {
        return Err(Error::Truncated);
    };
    if command != COMMAND_UDP_FORWARD {
        return Err(Error::UnknownCommand(command));
    }
    if host_len == UDP_REQUEST_IP_LEN {
        decode_udp_datagram(src, 2, parse_ip_tail)
    } else {
        decode_udp_datagram(src, 1, parse_domain_tail)
    }
}

pub fn encode_udp_response(
    dst: &mut [u8],
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<usize> {
    let header_len = udp_response_header_len(address)?;
    let marker: &[u8] = match address {
        AddressRef::Ip(_) => &[],
        AddressRef::Domain { .. } => &[ATYP_DOMAIN],
    };
    encode_udp_datagram(dst, header_len, marker, address, payload)
}

pub fn decode_udp_response(src: &[u8]) -> Result<UdpPacket<'_>> {
    match src.first() {
        None => Err(Error::Truncated),
        Some(&ATYP_DOMAIN) => decode_udp_datagram(src, 1, parse_domain_tail),
        Some(_) => decode_udp_datagram(src, 0, parse_ip_tail),
    }
}

pub fn udp_request_len(address: AddressRef<'_>, payload_len: usize) -> Result<usize> {
    Ok(udp_request_header_len(address)? + payload_len)
}

pub fn udp_response_len(address: AddressRef<'_>, payload_len: usize) -> Result<usize> {
    Ok(udp_response_header_len(address)? + payload_len)
}

fn udp_request_header_len(address: AddressRef<'_>) -> Result<usize> {
    let marker = if matches!(address, AddressRef::Ip(_)) {
        2
    } else {
        1
    };
    Ok(marker + udp_tail_len(address)?)
}

fn udp_response_header_len(address: AddressRef<'_>) -> Result<usize> {
    let marker = usize::from(matches!(address, AddressRef::Domain { .. }));
    Ok(marker + udp_tail_len(address)?)
}

fn udp_tail_len(address: AddressRef<'_>) -> Result<usize> {
    let addr_len = match address {
        AddressRef::Domain { host, .. } => {
            validate_domain(host)?;
            host.len()
        }
        AddressRef::Ip(SocketAddr::V4(_)) => 4,
        AddressRef::Ip(SocketAddr::V6(_)) => 16,
    };
    Ok(1 + addr_len + 2)
}

fn encode_udp_datagram(
    dst: &mut [u8],
    header_len: usize,
    marker: &[u8],
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<usize> {
    let needed = header_len + payload.len();
    let (header, payload_dst) = dst_prefix(dst, needed)?.split_at_mut(header_len);
    let (marker_dst, tail) = header.split_at_mut(marker.len());
    marker_dst.copy_from_slice(marker);
    let (v4, v6);
    let (tag, addr): (u8, &[u8]) = match address {
        AddressRef::Domain { host, .. } => (host.len() as u8, host.as_bytes()),
        AddressRef::Ip(SocketAddr::V4(ip)) => {
            v4 = ip.ip().octets();
            (ATYP_IPV4, &v4)
        }
        AddressRef::Ip(SocketAddr::V6(ip)) => {
            v6 = ip.ip().octets();
            (ATYP_IPV6, &v6)
        }
    };
    let (tag_dst, rest) = tail.split_at_mut(1);
    tag_dst[0] = tag;
    let (addr_dst, port_dst) = rest.split_at_mut(addr.len());
    addr_dst.copy_from_slice(addr);
    port_dst.copy_from_slice(&address.port().to_be_bytes());
    payload_dst.copy_from_slice(payload);
    Ok(needed)
}

fn decode_udp_datagram<'a>(
    src: &'a [u8],
    marker_len: usize,
    parse_tail: fn(&'a [u8]) -> Result<(AddressRef<'a>, usize)>,
) -> Result<UdpPacket<'a>> {
    let (address, tail_len) = parse_tail(&src[marker_len..])?;
    let header_len = marker_len + tail_len;
    Ok(UdpPacket {
        address,
        payload: &src[header_len..],
        header_len,
    })
}

fn parse_ip_tail(src: &[u8]) -> Result<(AddressRef<'_>, usize)> {
    let (&atyp, rest) = src.split_first().ok_or(Error::Truncated)?;
    let (addr, ip_len) = match atyp {
        ATYP_IPV4 => (ip_port::<4>(rest), 4),
        ATYP_IPV6 => (ip_port::<16>(rest), 16),
        other => return Err(Error::InvalidAddressType(other)),
    };
    let addr = addr.ok_or(Error::Truncated)?;
    Ok((AddressRef::Ip(addr), 1 + ip_len + 2))
}

fn parse_domain_tail(src: &[u8]) -> Result<(AddressRef<'_>, usize)> {
    let (host, port, len) = split_host_port(src)?;
    Ok((AddressRef::domain(host, port)?, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;

    #[test]
    fn connect_v2_matches_golden_shape() {
        let address = Address::domain("example.com", 443).unwrap();
        let mut out = [0; 17];
        let n = encode_connect_request(&mut out, address.as_view(), true).unwrap();
        assert_eq!(&out[..n], b"\x01\x05\x00\x0bexample.com\x01\xbb");
    }

    #[test]
    fn server_reply_tunnel_and_error() {
        match decode_server_reply(&[COMMAND_TUNNEL, 1, 2]).unwrap() {
            ParseState::Done((ServerReply::Tunnel, 1)) => {}
            other => panic!("{other:?}"),
        }
        match decode_server_reply(&[COMMAND_ERROR, ERROR_REJECT, 2, b'n', b'o', b'!']).unwrap() {
            ParseState::Done((ServerReply::Error { code, message }, 5)) => {
                assert_eq!(code, ERROR_REJECT);
                assert_eq!(message, b"no");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            decode_server_reply(&[COMMAND_ERROR, 1]),
            Ok(ParseState::Need(3))
        ));
    }

    #[test]
    fn connect_prefix_allows_early_payload() {
        let wire = b"\x01\x05\x03abc\x03dns\x01\xbbhello";
        let (request, consumed) = decode_connect_request_prefix(wire).unwrap();
        assert!(request.reuse);
        assert_eq!(consumed, wire.len() - 5);
        assert!(decode_connect_request(wire).is_err());
    }

    #[test]
    fn udp_request_ipv4_matches_golden() {
        let packet = decode_udp_request(b"\x01\x00\x04\x7f\x00\x00\x01\x1f\x90payload").unwrap();
        assert_eq!(packet.header_len, 9);
        assert_eq!(packet.payload, b"payload");
    }
}

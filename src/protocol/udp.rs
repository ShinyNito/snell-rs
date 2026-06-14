use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::BufMut;

use crate::error::{Error, Result};
use crate::parse::{read_array, read_be_u16, read_u8, take_bytes};
use crate::protocol::header::COMMAND_UDP_FORWARD;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressRef<'a> {
    Domain(&'a str),
    Ip(IpAddr),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPacketRef<'a> {
    pub address: AddressRef<'a>,
    pub port: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressWire {
    Request,
    Response,
}

/// Writes the Snell UDP request address prefix.
///
/// # Errors
///
/// Returns an error if a domain address is empty or exceeds the protocol's
/// one-byte domain length limit.
pub fn write_udp_request_prefix(
    out: &mut impl BufMut,
    address: AddressRef<'_>,
    port: u16,
) -> Result<()> {
    out.put_u8(COMMAND_UDP_FORWARD);
    write_address(out, address, port, AddressWire::Request)
}

/// Writes the Snell UDP response address prefix.
///
/// # Errors
///
/// Returns an error if a domain address is empty or exceeds the protocol's
/// one-byte domain length limit.
pub fn write_udp_response_prefix(
    out: &mut impl BufMut,
    address: AddressRef<'_>,
    port: u16,
) -> Result<()> {
    write_address(out, address, port, AddressWire::Response)
}

/// Parses a Snell UDP request packet as a borrowed view into `packet`.
///
/// Domain names and payload slices borrow from the original frame payload.
///
/// # Errors
///
/// Returns an error if the packet is malformed, truncated, has an unsupported
/// address type, or contains invalid UTF-8 in a domain.
pub fn parse_udp_request(packet: &[u8]) -> Result<UdpPacketRef<'_>> {
    let mut input = packet;
    let command = read_u8(&mut input, Error::InvalidUdpPacket)?;
    let address_len_or_zero = read_u8(&mut input, Error::InvalidUdpPacket)?;
    if command != COMMAND_UDP_FORWARD {
        return Err(Error::InvalidUdpPacket);
    }

    if address_len_or_zero != 0 {
        return parse_domain_packet(&mut input, address_len_or_zero as usize);
    }

    parse_ip_packet(&mut input)
}

/// Parses a Snell UDP response packet as a borrowed view into `packet`.
///
/// Domain names and payload slices borrow from the original frame payload.
///
/// # Errors
///
/// Returns an error if the packet is malformed, truncated, has an unsupported
/// address type, or contains invalid UTF-8 in a domain.
pub fn parse_udp_response(packet: &[u8]) -> Result<UdpPacketRef<'_>> {
    let mut input = packet;
    match read_u8(&mut input, Error::InvalidUdpPacket)? {
        0x03 => {
            let host_len = read_u8(&mut input, Error::TruncatedUdpPacket)? as usize;
            parse_domain_packet(&mut input, host_len)
        }
        0x04 => parse_ip_body(&mut input, 0x04),
        0x06 => parse_ip_body(&mut input, 0x06),
        _ => Err(Error::InvalidAddressType),
    }
}

fn write_address(
    out: &mut impl BufMut,
    address: AddressRef<'_>,
    port: u16,
    wire: AddressWire,
) -> Result<()> {
    match address {
        AddressRef::Domain(host) => {
            if host.is_empty() {
                return Err(Error::EmptyHost);
            }
            if host.len() > u8::MAX as usize {
                return Err(Error::HostTooLong);
            }
            if wire == AddressWire::Response {
                out.put_u8(0x03);
            }
            out.put_u8(u8::try_from(host.len()).map_err(|_| Error::HostTooLong)?);
            out.put_slice(host.as_bytes());
        }
        AddressRef::Ip(IpAddr::V4(ip)) => {
            if wire == AddressWire::Request {
                out.put_u8(0);
            }
            out.put_u8(0x04);
            out.put_slice(&ip.octets());
        }
        AddressRef::Ip(IpAddr::V6(ip)) => {
            if wire == AddressWire::Request {
                out.put_u8(0);
            }
            out.put_u8(0x06);
            out.put_slice(&ip.octets());
        }
    }
    out.put_u16(port);
    Ok(())
}

fn parse_domain_packet<'a>(input: &mut &'a [u8], host_len: usize) -> Result<UdpPacketRef<'a>> {
    let host = take_bytes(input, host_len, Error::TruncatedUdpPacket)?;
    let port = read_be_u16(input, Error::TruncatedUdpPacket)?;
    let payload: &'a [u8] = input;
    Ok(UdpPacketRef {
        address: AddressRef::Domain(std::str::from_utf8(host)?),
        port,
        payload,
    })
}

fn parse_ip_packet<'a>(input: &mut &'a [u8]) -> Result<UdpPacketRef<'a>> {
    let address_type = read_u8(input, Error::TruncatedUdpPacket)?;
    parse_ip_body(input, address_type)
}

fn parse_ip_body<'a>(input: &mut &'a [u8], address_type: u8) -> Result<UdpPacketRef<'a>> {
    match address_type {
        0x04 => {
            let octets = read_array::<4>(input, Error::TruncatedUdpPacket)?;
            let port = read_be_u16(input, Error::TruncatedUdpPacket)?;
            let payload: &'a [u8] = input;
            Ok(UdpPacketRef {
                address: AddressRef::Ip(IpAddr::V4(Ipv4Addr::from(octets))),
                port,
                payload,
            })
        }
        0x06 => {
            let octets = read_array::<16>(input, Error::TruncatedUdpPacket)?;
            let port = read_be_u16(input, Error::TruncatedUdpPacket)?;
            let payload: &'a [u8] = input;
            Ok(UdpPacketRef {
                address: AddressRef::Ip(IpAddr::V6(Ipv6Addr::from(octets))),
                port,
                payload,
            })
        }
        _ => Err(Error::InvalidAddressType),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use bytes::BytesMut;

    use super::{
        AddressRef, UdpPacketRef, parse_udp_request, parse_udp_response, write_udp_request_prefix,
        write_udp_response_prefix,
    };
    use crate::error::Error;

    #[test]
    fn writes_and_parses_domain_request_without_payload_copy() {
        let payload = b"dns query";
        let mut out = BytesMut::new();

        write_udp_request_prefix(&mut out, AddressRef::Domain("example.com"), 53).unwrap();
        out.extend_from_slice(payload);
        let parsed = parse_udp_request(&out).unwrap();

        assert_eq!(
            parsed,
            UdpPacketRef {
                address: AddressRef::Domain("example.com"),
                port: 53,
                payload
            }
        );
        assert!(std::ptr::eq(parsed.payload.as_ptr(), out[15..].as_ptr()));
    }

    #[test]
    fn writes_and_parses_ipv4_request() {
        let payload = b"hello";
        let mut out = BytesMut::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        write_udp_request_prefix(&mut out, AddressRef::Ip(ip), 443).unwrap();
        out.extend_from_slice(payload);
        let parsed = parse_udp_request(&out).unwrap();

        assert_eq!(parsed.address, AddressRef::Ip(ip));
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn writes_and_parses_ipv6_response() {
        let payload = b"world";
        let mut out = BytesMut::new();
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

        write_udp_response_prefix(&mut out, AddressRef::Ip(ip), 443).unwrap();
        out.extend_from_slice(payload);
        let parsed = parse_udp_response(&out).unwrap();

        assert_eq!(parsed.address, AddressRef::Ip(ip));
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn maps_udp_request_parse_errors() {
        assert!(matches!(
            parse_udp_request(&[]),
            Err(Error::InvalidUdpPacket)
        ));
        assert!(matches!(
            parse_udp_request(&[0xff, 0]),
            Err(Error::InvalidUdpPacket)
        ));
        assert!(matches!(
            parse_udp_request(&[crate::protocol::header::COMMAND_UDP_FORWARD, 3, b'a']),
            Err(Error::TruncatedUdpPacket)
        ));
    }

    #[test]
    fn maps_udp_response_parse_errors() {
        assert!(matches!(
            parse_udp_response(&[]),
            Err(Error::InvalidUdpPacket)
        ));
        assert!(matches!(
            parse_udp_response(&[0x04, 127, 0]),
            Err(Error::TruncatedUdpPacket)
        ));
        assert!(matches!(
            parse_udp_response(&[0xff]),
            Err(Error::InvalidAddressType)
        ));
    }
}

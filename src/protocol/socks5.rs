use core::range::Range;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::parse::{read_array, read_be_u16, read_u8, take_bytes};
use crate::protocol::udp::AddressRef;

pub const SOCKS_VERSION: u8 = 5;
pub const METHOD_NO_AUTH: u8 = 0;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xff;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_UDP_ASSOCIATE: u8 = 3;
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksRequest {
    Connect(SocksTarget),
    UdpAssociate(SocksTarget),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksAddress {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksBoundAddr {
    pub address: SocksAddress,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocksAddressContext {
    Request,
    Response,
}

impl SocksAddressContext {
    const fn invalid_error(self) -> Error {
        match self {
            Self::Request => Error::InvalidSocksRequest,
            Self::Response => Error::InvalidSocksResponse,
        }
    }

    const fn empty_domain_error(self) -> Error {
        match self {
            Self::Request => Error::EmptyHost,
            Self::Response => Error::InvalidSocksResponse,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocksUdpPacketRef<'a> {
    pub address: AddressRef<'a>,
    pub port: u16,
    pub payload_span: Range<usize>,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksReply {
    Succeeded = 0,
    GeneralFailure = 1,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

/// Parses a SOCKS5 UDP packet as a borrowed view into `packet`.
///
/// Domain names and payload slices borrow from the original datagram.
/// `payload_span` is the payload range in that datagram.
pub fn parse_udp_packet(packet: &[u8]) -> Result<SocksUdpPacketRef<'_>> {
    let mut input = packet;
    let header = take_bytes(&mut input, 3, Error::InvalidSocksRequest)?;
    if header != [0, 0, 0] {
        return Err(Error::InvalidSocksRequest);
    }

    parse_address(&mut input, 3)
}

pub fn write_udp_packet(
    out: &mut impl BufMut,
    address: AddressRef<'_>,
    port: u16,
    payload: &[u8],
) -> Result<()> {
    out.put_slice(&[0, 0, 0]);
    write_address(out, address, port)?;
    out.put_slice(payload);
    Ok(())
}

pub(crate) async fn read_address_port<S>(
    stream: &mut S,
    atyp: u8,
    context: SocksAddressContext,
) -> Result<(SocksAddress, u16)>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut raw = [0; 6];
            stream.read_exact(&mut raw).await?;
            let mut input = &raw[..];
            let octets = read_array::<4>(&mut input, context.invalid_error())?;
            let port = read_be_u16(&mut input, context.invalid_error())?;
            Ok((SocksAddress::Ip(IpAddr::V4(Ipv4Addr::from(octets))), port))
        }
        ATYP_DOMAIN => {
            let mut len = [0; 1];
            stream.read_exact(&mut len).await?;
            let host_len = len[0] as usize;
            if host_len == 0 {
                return Err(context.empty_domain_error());
            }

            let mut raw = [0; u8::MAX as usize + 2];
            stream.read_exact(&mut raw[..host_len + 2]).await?;
            let mut input = &raw[..host_len + 2];
            let host = take_bytes(&mut input, host_len, context.invalid_error())?;
            let port = read_be_u16(&mut input, context.invalid_error())?;
            Ok((
                SocksAddress::Domain(std::str::from_utf8(host)?.to_owned()),
                port,
            ))
        }
        ATYP_IPV6 => {
            let mut raw = [0; 18];
            stream.read_exact(&mut raw).await?;
            let mut input = &raw[..];
            let octets = read_array::<16>(&mut input, context.invalid_error())?;
            let port = read_be_u16(&mut input, context.invalid_error())?;
            Ok((SocksAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets))), port))
        }
        _ => Err(context.invalid_error()),
    }
}

fn parse_address<'a>(input: &mut &'a [u8], base_offset: usize) -> Result<SocksUdpPacketRef<'a>> {
    let original_len = input.len();
    match read_u8(input, Error::InvalidSocksRequest)? {
        ATYP_IPV4 => {
            let octets = read_array::<4>(input, Error::InvalidSocksRequest)?;
            let port = read_be_u16(input, Error::InvalidSocksRequest)?;
            let payload_start = base_offset + original_len - input.len();
            let payload: &'a [u8] = input;
            Ok(SocksUdpPacketRef {
                address: AddressRef::Ip(IpAddr::V4(Ipv4Addr::from(octets))),
                port,
                payload_span: Range {
                    start: payload_start,
                    end: payload_start + payload.len(),
                },
                payload,
            })
        }
        ATYP_DOMAIN => {
            let host_len = read_u8(input, Error::InvalidSocksRequest)? as usize;
            if host_len == 0 {
                return Err(Error::InvalidSocksRequest);
            }
            let host = take_bytes(input, host_len, Error::InvalidSocksRequest)?;
            let port = read_be_u16(input, Error::InvalidSocksRequest)?;
            let payload_start = base_offset + original_len - input.len();
            let payload: &'a [u8] = input;
            Ok(SocksUdpPacketRef {
                address: AddressRef::Domain(std::str::from_utf8(host)?),
                port,
                payload_span: Range {
                    start: payload_start,
                    end: payload_start + payload.len(),
                },
                payload,
            })
        }
        ATYP_IPV6 => {
            let octets = read_array::<16>(input, Error::InvalidSocksRequest)?;
            let port = read_be_u16(input, Error::InvalidSocksRequest)?;
            let payload_start = base_offset + original_len - input.len();
            let payload: &'a [u8] = input;
            Ok(SocksUdpPacketRef {
                address: AddressRef::Ip(IpAddr::V6(Ipv6Addr::from(octets))),
                port,
                payload_span: Range {
                    start: payload_start,
                    end: payload_start + payload.len(),
                },
                payload,
            })
        }
        _ => Err(Error::InvalidSocksRequest),
    }
}

pub(crate) fn write_address(
    out: &mut impl BufMut,
    address: AddressRef<'_>,
    port: u16,
) -> Result<()> {
    match address {
        AddressRef::Domain(host) => {
            if host.is_empty() {
                return Err(Error::EmptyHost);
            }
            if host.len() > u8::MAX as usize {
                return Err(Error::HostTooLong);
            }
            out.put_u8(ATYP_DOMAIN);
            out.put_u8(host.len() as u8);
            out.put_slice(host.as_bytes());
        }
        AddressRef::Ip(IpAddr::V4(ip)) => {
            out.put_u8(ATYP_IPV4);
            out.put_slice(&ip.octets());
        }
        AddressRef::Ip(IpAddr::V6(ip)) => {
            out.put_u8(ATYP_IPV6);
            out.put_slice(&ip.octets());
        }
    }
    out.put_u16(port);
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::range::Range;

    use bytes::BytesMut;

    use super::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, parse_udp_packet, write_udp_packet};
    use crate::error::Error;
    use crate::protocol::udp::AddressRef;

    #[test]
    fn writes_and_parses_udp_packet() {
        let mut out = BytesMut::new();

        write_udp_packet(&mut out, AddressRef::Domain("example.com"), 53, b"query").unwrap();
        let parsed = parse_udp_packet(&out).unwrap();

        assert_eq!(parsed.address, AddressRef::Domain("example.com"));
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload_span, Range { start: 18, end: 23 });
        assert_eq!(parsed.payload, b"query");
    }

    #[test]
    fn maps_udp_packet_parse_errors() {
        assert!(matches!(
            parse_udp_packet(&[0, 0]),
            Err(Error::InvalidSocksRequest)
        ));
        assert!(matches!(
            parse_udp_packet(&[0, 0, 1, ATYP_IPV4, 127, 0, 0, 1, 0, 53]),
            Err(Error::InvalidSocksRequest)
        ));
        assert!(matches!(
            parse_udp_packet(&[0, 0, 0, ATYP_DOMAIN, 0, 0, 53]),
            Err(Error::InvalidSocksRequest)
        ));
        assert!(matches!(
            parse_udp_packet(&[0, 0, 0, ATYP_IPV6, 0, 0]),
            Err(Error::InvalidSocksRequest)
        ));
    }
}

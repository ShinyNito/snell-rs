use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::address::{Address, AddressRef, validate_domain};
use crate::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_ERROR,
    COMMAND_TUNNEL, COMMAND_UDP, COMMAND_UDP_FORWARD, ERROR_REJECT, Error, PROTOCOL_VERSION,
    ParseState, Result, UDP_REQUEST_IP_LEN,
};

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
    let host = destination.host();
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(Error::HostTooLong);
    }
    Ok(4 + host.len() + 2)
}

pub fn encode_connect_request(
    dst: &mut [u8],
    destination: AddressRef<'_>,
    reuse: bool,
) -> Result<usize> {
    let needed = connect_request_len(destination)?;
    if dst.len() < needed {
        return Err(Error::BufferTooSmall {
            needed,
            available: dst.len(),
        });
    }
    let host = destination.host();
    let host = host.as_bytes();
    dst[0] = PROTOCOL_VERSION;
    dst[1] = if reuse {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    };
    dst[2] = 0;
    dst[3] = host.len() as u8;
    dst[4..4 + host.len()].copy_from_slice(host);
    dst[4 + host.len()..needed].copy_from_slice(&destination.port().to_be_bytes());
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
    if src.len() < 3 {
        return Err(Error::Truncated);
    }
    if src[0] != PROTOCOL_VERSION {
        return Err(Error::InvalidVersion(src[0]));
    }
    let reuse = match src[1] {
        COMMAND_CONNECT => false,
        COMMAND_CONNECT_V2 => true,
        other => return Err(Error::UnknownCommand(other)),
    };
    let client_id_len = src[2] as usize;
    let host_len_offset = 3 + client_id_len;
    if src.len() <= host_len_offset {
        return Err(Error::Truncated);
    }
    let host_len = src[host_len_offset] as usize;
    if host_len == 0 {
        return Err(Error::EmptyHost);
    }
    let host_offset = host_len_offset + 1;
    let needed = host_offset + host_len + 2;
    if src.len() < needed {
        return Err(Error::Truncated);
    }
    let host = std::str::from_utf8(&src[host_offset..host_offset + host_len])
        .map_err(|_| Error::InvalidHostUtf8)?;
    let port = u16::from_be_bytes([src[host_offset + host_len], src[host_offset + host_len + 1]]);
    let destination = if let Ok(ip) = host.parse::<IpAddr>() {
        Address::Ip(SocketAddr::new(ip, port))
    } else {
        Address::domain(host, port)?
    };
    Ok((ConnectRequest { destination, reuse }, needed))
}

pub fn encode_udp_setup(dst: &mut [u8]) -> Result<usize> {
    if dst.len() < 3 {
        return Err(Error::BufferTooSmall {
            needed: 3,
            available: dst.len(),
        });
    }
    dst[0] = PROTOCOL_VERSION;
    dst[1] = COMMAND_UDP;
    dst[2] = 0;
    Ok(3)
}

pub fn decode_udp_setup_prefix(src: &[u8]) -> Result<usize> {
    if src.len() < 3 {
        return Err(Error::Truncated);
    }
    if src[0] != PROTOCOL_VERSION {
        return Err(Error::InvalidVersion(src[0]));
    }
    if src[1] != COMMAND_UDP {
        return Err(Error::UnknownCommand(src[1]));
    }
    let needed = 3 + src[2] as usize;
    if src.len() < needed {
        return Err(Error::Truncated);
    }
    Ok(needed)
}

pub fn encode_tunnel_reply(dst: &mut [u8]) -> Result<usize> {
    if dst.is_empty() {
        return Err(Error::BufferTooSmall {
            needed: 1,
            available: 0,
        });
    }
    dst[0] = COMMAND_TUNNEL;
    Ok(1)
}

pub fn encode_error_reply(dst: &mut [u8], code: u8, message: &str) -> Result<usize> {
    let msg = message.as_bytes();
    let msg_len = msg.len().min(255);
    let needed = 3 + msg_len;
    if dst.len() < needed {
        return Err(Error::BufferTooSmall {
            needed,
            available: dst.len(),
        });
    }
    dst[0] = COMMAND_ERROR;
    dst[1] = code;
    dst[2] = msg_len as u8;
    dst[3..needed].copy_from_slice(&msg[..msg_len]);
    Ok(needed)
}

pub fn encode_reject(dst: &mut [u8], message: &str) -> Result<usize> {
    encode_error_reply(dst, ERROR_REJECT, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerReply<'a> {
    Tunnel,
    Error { code: u8, message: &'a [u8] },
}

pub fn decode_server_reply(src: &[u8]) -> Result<ParseState<(ServerReply<'_>, usize)>> {
    if src.is_empty() {
        return Ok(ParseState::Need(1));
    }
    match src[0] {
        COMMAND_TUNNEL => Ok(ParseState::Done((ServerReply::Tunnel, 1))),
        COMMAND_ERROR => {
            if src.len() < 3 {
                return Ok(ParseState::Need(3));
            }
            let msg_len = src[2] as usize;
            let needed = 3 + msg_len;
            if src.len() < needed {
                return Ok(ParseState::Need(needed));
            }
            Ok(ParseState::Done((
                ServerReply::Error {
                    code: src[1],
                    message: &src[3..needed],
                },
                needed,
            )))
        }
        other => Err(Error::UnknownCommand(other)),
    }
}

pub fn encode_udp_request(
    dst: &mut [u8],
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<usize> {
    let header_len = udp_request_header_len(address)?;
    let needed = header_len + payload.len();
    if dst.len() < needed {
        return Err(Error::BufferTooSmall {
            needed,
            available: dst.len(),
        });
    }
    write_udp_request_header(&mut dst[..header_len], address)?;
    dst[header_len..needed].copy_from_slice(payload);
    Ok(needed)
}

pub fn decode_udp_request(src: &[u8]) -> Result<UdpPacket<'_>> {
    if src.len() < 2 {
        return Err(Error::Truncated);
    }
    if src[0] != COMMAND_UDP_FORWARD {
        return Err(Error::UnknownCommand(src[0]));
    }
    if src[1] == UDP_REQUEST_IP_LEN {
        if src.len() < 3 {
            return Err(Error::Truncated);
        }
        return match src[2] {
            ATYP_IPV4 => {
                if src.len() < 9 {
                    return Err(Error::Truncated);
                }
                let ip = Ipv4Addr::new(src[3], src[4], src[5], src[6]);
                let port = u16::from_be_bytes([src[7], src[8]]);
                Ok(UdpPacket {
                    address: AddressRef::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                    payload: &src[9..],
                    header_len: 9,
                })
            }
            ATYP_IPV6 => {
                if src.len() < 21 {
                    return Err(Error::Truncated);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&src[3..19]);
                let port = u16::from_be_bytes([src[19], src[20]]);
                Ok(UdpPacket {
                    address: AddressRef::Ip(SocketAddr::new(IpAddr::V6(octets.into()), port)),
                    payload: &src[21..],
                    header_len: 21,
                })
            }
            other => Err(Error::InvalidAddressType(other)),
        };
    }
    let host_len = src[1] as usize;
    let needed = 2 + host_len + 2;
    if src.len() < needed {
        return Err(Error::Truncated);
    }
    let host = std::str::from_utf8(&src[2..2 + host_len]).map_err(|_| Error::InvalidHostUtf8)?;
    validate_domain(host)?;
    let port = u16::from_be_bytes([src[2 + host_len], src[2 + host_len + 1]]);
    Ok(UdpPacket {
        address: AddressRef::Domain { host, port },
        payload: &src[needed..],
        header_len: needed,
    })
}

pub fn encode_udp_response(
    dst: &mut [u8],
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<usize> {
    let header_len = udp_response_header_len(address)?;
    let needed = header_len + payload.len();
    if dst.len() < needed {
        return Err(Error::BufferTooSmall {
            needed,
            available: dst.len(),
        });
    }
    write_udp_response_header(&mut dst[..header_len], address)?;
    dst[header_len..needed].copy_from_slice(payload);
    Ok(needed)
}

pub fn decode_udp_response(src: &[u8]) -> Result<UdpPacket<'_>> {
    if src.is_empty() {
        return Err(Error::Truncated);
    }
    match src[0] {
        ATYP_DOMAIN => {
            if src.len() < 2 {
                return Err(Error::Truncated);
            }
            let host_len = src[1] as usize;
            let needed = 2 + host_len + 2;
            if src.len() < needed {
                return Err(Error::Truncated);
            }
            let host =
                std::str::from_utf8(&src[2..2 + host_len]).map_err(|_| Error::InvalidHostUtf8)?;
            validate_domain(host)?;
            let port = u16::from_be_bytes([src[2 + host_len], src[2 + host_len + 1]]);
            Ok(UdpPacket {
                address: AddressRef::Domain { host, port },
                payload: &src[needed..],
                header_len: needed,
            })
        }
        ATYP_IPV4 => {
            if src.len() < 7 {
                return Err(Error::Truncated);
            }
            let ip = Ipv4Addr::new(src[1], src[2], src[3], src[4]);
            let port = u16::from_be_bytes([src[5], src[6]]);
            Ok(UdpPacket {
                address: AddressRef::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                payload: &src[7..],
                header_len: 7,
            })
        }
        ATYP_IPV6 => {
            if src.len() < 19 {
                return Err(Error::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&src[1..17]);
            let port = u16::from_be_bytes([src[17], src[18]]);
            Ok(UdpPacket {
                address: AddressRef::Ip(SocketAddr::new(IpAddr::V6(octets.into()), port)),
                payload: &src[19..],
                header_len: 19,
            })
        }
        other => Err(Error::InvalidAddressType(other)),
    }
}

pub fn udp_request_len(address: AddressRef<'_>, payload_len: usize) -> Result<usize> {
    Ok(udp_request_header_len(address)? + payload_len)
}

pub fn udp_response_len(address: AddressRef<'_>, payload_len: usize) -> Result<usize> {
    Ok(udp_response_header_len(address)? + payload_len)
}

fn udp_request_header_len(address: AddressRef<'_>) -> Result<usize> {
    match address {
        AddressRef::Domain { host, .. } => {
            validate_domain(host)?;
            Ok(1 + 1 + host.len() + 2)
        }
        AddressRef::Ip(SocketAddr::V4(_)) => Ok(9),
        AddressRef::Ip(SocketAddr::V6(_)) => Ok(21),
    }
}

fn write_udp_request_header(dst: &mut [u8], address: AddressRef<'_>) -> Result<()> {
    match address {
        AddressRef::Domain { host, port } => {
            let host = host.as_bytes();
            dst[0] = COMMAND_UDP_FORWARD;
            dst[1] = host.len() as u8;
            dst[2..2 + host.len()].copy_from_slice(host);
            dst[2 + host.len()..].copy_from_slice(&port.to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V4(addr)) => {
            dst[0] = COMMAND_UDP_FORWARD;
            dst[1] = UDP_REQUEST_IP_LEN;
            dst[2] = ATYP_IPV4;
            dst[3..7].copy_from_slice(&addr.ip().octets());
            dst[7..9].copy_from_slice(&addr.port().to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V6(addr)) => {
            dst[0] = COMMAND_UDP_FORWARD;
            dst[1] = UDP_REQUEST_IP_LEN;
            dst[2] = ATYP_IPV6;
            dst[3..19].copy_from_slice(&addr.ip().octets());
            dst[19..21].copy_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(())
}

fn udp_response_header_len(address: AddressRef<'_>) -> Result<usize> {
    match address {
        AddressRef::Domain { host, .. } => {
            validate_domain(host)?;
            Ok(1 + 1 + host.len() + 2)
        }
        AddressRef::Ip(SocketAddr::V4(_)) => Ok(7),
        AddressRef::Ip(SocketAddr::V6(_)) => Ok(19),
    }
}

fn write_udp_response_header(dst: &mut [u8], address: AddressRef<'_>) -> Result<()> {
    match address {
        AddressRef::Domain { host, port } => {
            let host = host.as_bytes();
            dst[0] = ATYP_DOMAIN;
            dst[1] = host.len() as u8;
            dst[2..2 + host.len()].copy_from_slice(host);
            dst[2 + host.len()..].copy_from_slice(&port.to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V4(addr)) => {
            dst[0] = ATYP_IPV4;
            dst[1..5].copy_from_slice(&addr.ip().octets());
            dst[5..7].copy_from_slice(&addr.port().to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V6(addr)) => {
            dst[0] = ATYP_IPV6;
            dst[1..17].copy_from_slice(&addr.ip().octets());
            dst[17..19].copy_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(())
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

    #[test]
    fn encode_matches_workspace_connect_golden() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/connect-example-com-443.json");
        let raw = std::fs::read_to_string(path).unwrap();
        let hex = raw
            .split("\"hex\"")
            .nth(1)
            .unwrap()
            .split('"')
            .nth(1)
            .unwrap();
        let expected = decode_hex(hex);
        let address = Address::domain("example.com", 443).unwrap();
        let mut out = [0; 32];
        let n = encode_connect_request(&mut out, address.as_view(), false).unwrap();
        assert_eq!(&out[..n], expected);
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        let hex: String = hex.chars().filter(|ch| !ch.is_whitespace()).collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}

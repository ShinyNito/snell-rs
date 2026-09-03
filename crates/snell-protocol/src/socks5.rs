use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::address::AddressRef;
use crate::{Error, ParseState, Result};

pub const VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xff;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Other(u8),
}

impl Command {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            CMD_CONNECT => Self::Connect,
            CMD_BIND => Self::Bind,
            CMD_UDP_ASSOCIATE => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Connect => CMD_CONNECT,
            Self::Bind => CMD_BIND,
            Self::UdpAssociate => CMD_UDP_ASSOCIATE,
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Other(u8),
}

impl Reply {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::Succeeded,
            0x01 => Self::GeneralFailure,
            0x02 => Self::ConnectionNotAllowed,
            0x03 => Self::NetworkUnreachable,
            0x04 => Self::HostUnreachable,
            0x05 => Self::ConnectionRefused,
            0x06 => Self::TtlExpired,
            0x07 => Self::CommandNotSupported,
            0x08 => Self::AddressTypeNotSupported,
            other => Self::Other(other),
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::ConnectionNotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
            Self::Other(value) => value,
        }
    }

    pub fn from_io_error(err: &std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset => {
                Self::GeneralFailure
            }
            std::io::ErrorKind::TimedOut => Self::TtlExpired,
            std::io::ErrorKind::NotFound => Self::HostUnreachable,
            std::io::ErrorKind::AddrNotAvailable => Self::AddressTypeNotSupported,
            _ => Self::GeneralFailure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreetingRef<'a> {
    pub methods: &'a [u8],
    pub consumed_len: usize,
}

impl GreetingRef<'_> {
    pub fn supports(self, method: u8) -> bool {
        self.methods.contains(&method)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestRef<'a> {
    pub command: Command,
    pub destination: AddressRef<'a>,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyRef<'a> {
    pub reply: Reply,
    pub bind: AddressRef<'a>,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketRef<'a> {
    pub frag: u8,
    pub destination: AddressRef<'a>,
    pub header_len: usize,
    pub payload: &'a [u8],
}

pub fn greeting_need(buf: &[u8]) -> Result<ParseState<GreetingRef<'_>>> {
    if buf.len() < 2 {
        return Ok(ParseState::Need(2));
    }
    if buf[0] != VERSION {
        return Err(Error::InvalidVersion(buf[0]));
    }
    let nmethods = usize::from(buf[1]);
    if nmethods == 0 {
        return Err(Error::Malformed("empty method list"));
    }
    let total = 2 + nmethods;
    if buf.len() < total {
        return Ok(ParseState::Need(total));
    }
    Ok(ParseState::Done(GreetingRef {
        methods: &buf[2..total],
        consumed_len: total,
    }))
}

pub fn encode_greeting(dst: &mut [u8], methods: &[u8]) -> Result<usize> {
    if methods.is_empty() {
        return Err(Error::Malformed("empty method list"));
    }
    let needed = 2 + methods.len();
    ensure_capacity(dst, needed)?;
    dst[0] = VERSION;
    dst[1] = methods.len() as u8;
    dst[2..needed].copy_from_slice(methods);
    Ok(needed)
}

pub fn encode_method_selection(dst: &mut [u8], method: u8) -> Result<usize> {
    ensure_capacity(dst, 2)?;
    dst[0] = VERSION;
    dst[1] = method;
    Ok(2)
}

pub fn method_selection_need(buf: &[u8]) -> Result<ParseState<u8>> {
    if buf.len() < 2 {
        return Ok(ParseState::Need(2));
    }
    if buf[0] != VERSION {
        return Err(Error::InvalidVersion(buf[0]));
    }
    Ok(ParseState::Done(buf[1]))
}

pub fn request_need(buf: &[u8]) -> Result<ParseState<RequestRef<'_>>> {
    parse_cmd_addr(buf, |command, destination, header_len| RequestRef {
        command: Command::from_u8(command),
        destination,
        header_len,
    })
}

pub fn encode_request(
    dst: &mut [u8],
    command: Command,
    destination: AddressRef<'_>,
) -> Result<usize> {
    encode_cmd_addr(dst, command.to_u8(), destination)
}

pub fn reply_need(buf: &[u8]) -> Result<ParseState<ReplyRef<'_>>> {
    parse_cmd_addr(buf, |rep, bind, header_len| ReplyRef {
        reply: Reply::from_u8(rep),
        bind,
        header_len,
    })
}

pub fn encode_reply(dst: &mut [u8], reply: Reply, bind: AddressRef<'_>) -> Result<usize> {
    encode_cmd_addr(dst, reply.to_u8(), bind)
}

pub fn parse_udp_packet(buf: &[u8]) -> Result<UdpPacketRef<'_>> {
    if buf.len() < 4 {
        return Err(Error::Truncated);
    }
    if buf[0] != 0 || buf[1] != 0 {
        return Err(Error::InvalidReserved(buf[0] | buf[1]));
    }
    let (destination, addr_len) = parse_addr_field(&buf[3..])?;
    let header_len = 3 + addr_len;
    if buf.len() < header_len {
        return Err(Error::Truncated);
    }
    Ok(UdpPacketRef {
        frag: buf[2],
        destination,
        header_len,
        payload: &buf[header_len..],
    })
}

pub fn encode_udp_header(dst: &mut [u8], frag: u8, destination: AddressRef<'_>) -> Result<usize> {
    let addr_len = encoded_addr_len(destination)?;
    let needed = 3 + addr_len;
    ensure_capacity(dst, needed)?;
    dst[0] = 0;
    dst[1] = 0;
    dst[2] = frag;
    encode_addr_field(&mut dst[3..], destination)?;
    Ok(needed)
}

pub fn encode_udp_packet(
    dst: &mut [u8],
    frag: u8,
    destination: AddressRef<'_>,
    payload: &[u8],
) -> Result<usize> {
    let header_len = encode_udp_header(dst, frag, destination)?;
    let needed = header_len + payload.len();
    ensure_capacity(dst, needed)?;
    dst[header_len..needed].copy_from_slice(payload);
    Ok(needed)
}

fn parse_cmd_addr<'a, T>(
    buf: &'a [u8],
    build: impl FnOnce(u8, AddressRef<'a>, usize) -> T,
) -> Result<ParseState<T>> {
    if buf.len() < 4 {
        return Ok(ParseState::Need(4));
    }
    if buf[0] != VERSION {
        return Err(Error::InvalidVersion(buf[0]));
    }
    if buf[2] != 0 {
        return Err(Error::InvalidReserved(buf[2]));
    }
    match addr_len_need(&buf[3..])? {
        None => Ok(ParseState::Need(if buf[3] == ATYP_DOMAIN { 5 } else { 4 })),
        Some(addr_len) => {
            let total = 3 + addr_len;
            if buf.len() < total {
                return Ok(ParseState::Need(total));
            }
            let (destination, _) = parse_addr_field(&buf[3..])?;
            Ok(ParseState::Done(build(buf[1], destination, total)))
        }
    }
}

fn encode_cmd_addr(dst: &mut [u8], cmd: u8, address: AddressRef<'_>) -> Result<usize> {
    let addr_len = encoded_addr_len(address)?;
    let needed = 3 + addr_len;
    ensure_capacity(dst, needed)?;
    dst[0] = VERSION;
    dst[1] = cmd;
    dst[2] = 0;
    encode_addr_field(&mut dst[3..], address)?;
    Ok(needed)
}

fn addr_len_need(buf: &[u8]) -> Result<Option<usize>> {
    if buf.is_empty() {
        return Ok(None);
    }
    match buf[0] {
        ATYP_IPV4 => Ok(Some(1 + 4 + 2)),
        ATYP_IPV6 => Ok(Some(1 + 16 + 2)),
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Ok(None);
            }
            let len = usize::from(buf[1]);
            if len == 0 {
                return Err(Error::EmptyHost);
            }
            Ok(Some(1 + 1 + len + 2))
        }
        other => Err(Error::InvalidAddressType(other)),
    }
}

fn encoded_addr_len(address: AddressRef<'_>) -> Result<usize> {
    match address {
        AddressRef::Ip(SocketAddr::V4(_)) => Ok(7),
        AddressRef::Ip(SocketAddr::V6(_)) => Ok(19),
        AddressRef::Domain { host, .. } => {
            if host.is_empty() {
                return Err(Error::EmptyHost);
            }
            if host.len() > 255 {
                return Err(Error::HostTooLong);
            }
            Ok(1 + 1 + host.len() + 2)
        }
    }
}

fn encode_addr_field(dst: &mut [u8], address: AddressRef<'_>) -> Result<usize> {
    match address {
        AddressRef::Ip(SocketAddr::V4(v4)) => {
            dst[0] = ATYP_IPV4;
            dst[1..5].copy_from_slice(&v4.ip().octets());
            dst[5..7].copy_from_slice(&v4.port().to_be_bytes());
            Ok(7)
        }
        AddressRef::Ip(SocketAddr::V6(v6)) => {
            dst[0] = ATYP_IPV6;
            dst[1..17].copy_from_slice(&v6.ip().octets());
            dst[17..19].copy_from_slice(&v6.port().to_be_bytes());
            Ok(19)
        }
        AddressRef::Domain { host, port } => {
            let host = host.as_bytes();
            dst[0] = ATYP_DOMAIN;
            dst[1] = host.len() as u8;
            dst[2..2 + host.len()].copy_from_slice(host);
            dst[2 + host.len()..2 + host.len() + 2].copy_from_slice(&port.to_be_bytes());
            Ok(1 + 1 + host.len() + 2)
        }
    }
}

fn parse_addr_field(buf: &[u8]) -> Result<(AddressRef<'_>, usize)> {
    if buf.is_empty() {
        return Err(Error::Truncated);
    }
    match buf[0] {
        ATYP_IPV4 => {
            if buf.len() < 7 {
                return Err(Error::Truncated);
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((AddressRef::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7))
        }
        ATYP_IPV6 => {
            if buf.len() < 19 {
                return Err(Error::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                AddressRef::Ip(SocketAddr::new(IpAddr::V6(octets.into()), port)),
                19,
            ))
        }
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Err(Error::Truncated);
            }
            let host_len = usize::from(buf[1]);
            if host_len == 0 {
                return Err(Error::EmptyHost);
            }
            let needed = 2 + host_len + 2;
            if buf.len() < needed {
                return Err(Error::Truncated);
            }
            let host =
                std::str::from_utf8(&buf[2..2 + host_len]).map_err(|_| Error::InvalidHostUtf8)?;
            let port = u16::from_be_bytes([buf[2 + host_len], buf[2 + host_len + 1]]);
            Ok((AddressRef::Domain { host, port }, needed))
        }
        other => Err(Error::InvalidAddressType(other)),
    }
}

fn ensure_capacity(dst: &[u8], needed: usize) -> Result<()> {
    if dst.len() < needed {
        Err(Error::BufferTooSmall {
            needed,
            available: dst.len(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParseState;

    #[test]
    fn greeting_and_connect_round_trip() {
        let mut buf = [0u8; 64];
        let n = encode_greeting(&mut buf, &[METHOD_NO_AUTH]).unwrap();
        let ParseState::Done(g) = greeting_need(&buf[..n]).unwrap() else {
            panic!("need");
        };
        assert!(g.supports(METHOD_NO_AUTH));

        let n = encode_request(
            &mut buf,
            Command::Connect,
            AddressRef::Domain {
                host: "example.com",
                port: 443,
            },
        )
        .unwrap();
        let ParseState::Done(req) = request_need(&buf[..n]).unwrap() else {
            panic!("need");
        };
        assert_eq!(req.command, Command::Connect);
        assert_eq!(req.header_len, n);
    }

    #[test]
    fn request_need_grows_for_domain() {
        let partial = [VERSION, CMD_CONNECT, 0, ATYP_DOMAIN, 11];
        let ParseState::Need(total) = request_need(&partial).unwrap() else {
            panic!("need");
        };
        assert_eq!(total, 3 + 1 + 1 + 11 + 2);
    }
}

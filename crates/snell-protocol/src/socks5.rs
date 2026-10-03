use std::net::SocketAddr;

use crate::address::{AddressRef, ip_port, split_host_port};
use crate::error::dst_prefix;
use crate::{Error, MAX_DOMAIN_LEN, ParseState, Result};

pub const VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xff;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// Largest greeting: `VER NMETHODS METHODS(255)`.
pub const MAX_GREETING_LEN: usize = 2 + 255;

/// Largest request or reply: `VER CMD RSV ATYP LEN HOST(255) PORT(2)`.
pub const MAX_REQUEST_LEN: usize = 3 + 1 + 1 + MAX_DOMAIN_LEN + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Other(u8),
}

impl From<u8> for Command {
    fn from(value: u8) -> Self {
        match value {
            CMD_CONNECT => Self::Connect,
            CMD_BIND => Self::Bind,
            CMD_UDP_ASSOCIATE => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }
}

impl From<Command> for u8 {
    fn from(command: Command) -> Self {
        match command {
            Command::Connect => CMD_CONNECT,
            Command::Bind => CMD_BIND,
            Command::UdpAssociate => CMD_UDP_ASSOCIATE,
            Command::Other(value) => value,
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

impl From<u8> for Reply {
    fn from(value: u8) -> Self {
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
}

impl From<Reply> for u8 {
    fn from(reply: Reply) -> Self {
        match reply {
            Reply::Succeeded => 0x00,
            Reply::GeneralFailure => 0x01,
            Reply::ConnectionNotAllowed => 0x02,
            Reply::NetworkUnreachable => 0x03,
            Reply::HostUnreachable => 0x04,
            Reply::ConnectionRefused => 0x05,
            Reply::TtlExpired => 0x06,
            Reply::CommandNotSupported => 0x07,
            Reply::AddressTypeNotSupported => 0x08,
            Reply::Other(value) => value,
        }
    }
}

impl Reply {
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
    let [version, nmethods, ref methods @ ..] = *buf else {
        return Ok(ParseState::Need(2));
    };
    if version != VERSION {
        return Err(Error::InvalidVersion(version));
    }
    if nmethods == 0 {
        return Err(Error::Malformed("empty method list"));
    }
    let total = 2 + usize::from(nmethods);
    Ok(match methods.get(..usize::from(nmethods)) {
        Some(methods) => ParseState::Done(GreetingRef {
            methods,
            consumed_len: total,
        }),
        None => ParseState::Need(total),
    })
}

pub fn encode_greeting(dst: &mut [u8], methods: &[u8]) -> Result<usize> {
    if methods.is_empty() {
        return Err(Error::Malformed("empty method list"));
    }
    let needed = 2 + methods.len();
    let (head, tail) = dst_prefix(dst, needed)?.split_at_mut(2);
    head.copy_from_slice(&[VERSION, methods.len() as u8]);
    tail.copy_from_slice(methods);
    Ok(needed)
}

pub fn encode_method_selection(dst: &mut [u8], method: u8) -> Result<usize> {
    dst_prefix(dst, 2)?.copy_from_slice(&[VERSION, method]);
    Ok(2)
}

pub fn method_selection_need(buf: &[u8]) -> Result<ParseState<u8>> {
    match *buf {
        [VERSION, method, ..] => Ok(ParseState::Done(method)),
        [version, _, ..] => Err(Error::InvalidVersion(version)),
        _ => Ok(ParseState::Need(2)),
    }
}

pub fn request_need(buf: &[u8]) -> Result<ParseState<RequestRef<'_>>> {
    parse_cmd_addr(buf, |command, destination, header_len| RequestRef {
        command: command.into(),
        destination,
        header_len,
    })
}

pub fn encode_request(
    dst: &mut [u8],
    command: Command,
    destination: AddressRef<'_>,
) -> Result<usize> {
    encode_three_addr(dst, [VERSION, command.into(), 0], destination)
}

pub fn reply_need(buf: &[u8]) -> Result<ParseState<ReplyRef<'_>>> {
    parse_cmd_addr(buf, |rep, bind, header_len| ReplyRef {
        reply: rep.into(),
        bind,
        header_len,
    })
}

pub fn encode_reply(dst: &mut [u8], reply: Reply, bind: AddressRef<'_>) -> Result<usize> {
    encode_three_addr(dst, [VERSION, reply.into(), 0], bind)
}

pub fn parse_udp_packet(buf: &[u8]) -> Result<UdpPacketRef<'_>> {
    if buf.len() < 4 {
        return Err(Error::Truncated);
    }
    if buf[0] != 0 || buf[1] != 0 {
        return Err(Error::InvalidReserved(buf[0] | buf[1]));
    }
    let ParseState::Done((destination, addr_len)) = parse_addr(&buf[3..])? else {
        return Err(Error::Truncated);
    };
    let header_len = 3 + addr_len;
    Ok(UdpPacketRef {
        frag: buf[2],
        destination,
        header_len,
        payload: &buf[header_len..],
    })
}

pub fn encode_udp_header(dst: &mut [u8], frag: u8, destination: AddressRef<'_>) -> Result<usize> {
    encode_three_addr(dst, [0, 0, frag], destination)
}

pub fn encode_udp_packet(
    dst: &mut [u8],
    frag: u8,
    destination: AddressRef<'_>,
    payload: &[u8],
) -> Result<usize> {
    let header_len = 3 + encoded_addr_len(destination)?;
    let needed = header_len + payload.len();
    let (header, payload_dst) = dst_prefix(dst, needed)?.split_at_mut(header_len);
    write_three_addr(header, [0, 0, frag], destination);
    payload_dst.copy_from_slice(payload);
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
    Ok(match parse_addr(&buf[3..])? {
        ParseState::Need(n) => ParseState::Need(3 + n),
        ParseState::Done((address, len)) => ParseState::Done(build(buf[1], address, 3 + len)),
    })
}

/// `head(3) ATYP ADDR PORT`, the shape shared by requests, replies and UDP headers.
fn encode_three_addr(dst: &mut [u8], head: [u8; 3], address: AddressRef<'_>) -> Result<usize> {
    let needed = 3 + encoded_addr_len(address)?;
    write_three_addr(dst_prefix(dst, needed)?, head, address);
    Ok(needed)
}

/// `dst` is exactly `3 + encoded_addr_len(address)` bytes.
fn write_three_addr(dst: &mut [u8], head: [u8; 3], address: AddressRef<'_>) {
    let (head_dst, field) = dst.split_at_mut(3);
    head_dst.copy_from_slice(&head);
    let (tag, addr): (&[u8], &[u8]) = match &address {
        AddressRef::Ip(SocketAddr::V4(v4)) => (&[ATYP_IPV4], &v4.ip().octets()),
        AddressRef::Ip(SocketAddr::V6(v6)) => (&[ATYP_IPV6], &v6.ip().octets()),
        AddressRef::Domain { host, .. } => (&[ATYP_DOMAIN, host.len() as u8], host.as_bytes()),
    };
    let (tag_dst, rest) = field.split_at_mut(tag.len());
    tag_dst.copy_from_slice(tag);
    let (addr_dst, port_dst) = rest.split_at_mut(addr.len());
    addr_dst.copy_from_slice(addr);
    port_dst.copy_from_slice(&address.port().to_be_bytes());
}

fn encoded_addr_len(address: AddressRef<'_>) -> Result<usize> {
    match address {
        AddressRef::Ip(SocketAddr::V4(_)) => Ok(1 + 4 + 2),
        AddressRef::Ip(SocketAddr::V6(_)) => Ok(1 + 16 + 2),
        AddressRef::Domain { host, .. } => {
            if host.is_empty() {
                return Err(Error::EmptyHost);
            }
            if host.len() > MAX_DOMAIN_LEN {
                return Err(Error::HostTooLong);
            }
            Ok(1 + 1 + host.len() + 2)
        }
    }
}

/// `ATYP ADDR PORT` at the start of `buf`, validated in one pass. `Need`
/// counts from `buf[0]`.
fn parse_addr(buf: &[u8]) -> Result<ParseState<(AddressRef<'_>, usize)>> {
    let len = match *buf {
        [] => return Ok(ParseState::Need(1)),
        [ATYP_IPV4, ..] => 1 + 4 + 2,
        [ATYP_IPV6, ..] => 1 + 16 + 2,
        [ATYP_DOMAIN] => return Ok(ParseState::Need(2)),
        [ATYP_DOMAIN, 0, ..] => return Err(Error::EmptyHost),
        [ATYP_DOMAIN, host_len, ..] => 1 + 1 + usize::from(host_len) + 2,
        [other, ..] => return Err(Error::InvalidAddressType(other)),
    };
    if buf.len() < len {
        return Ok(ParseState::Need(len));
    }
    let tail = &buf[1..];
    let address = match buf[0] {
        ATYP_IPV4 => AddressRef::Ip(ip_port::<4>(tail).ok_or(Error::Truncated)?),
        ATYP_IPV6 => AddressRef::Ip(ip_port::<16>(tail).ok_or(Error::Truncated)?),
        _ => {
            let (host, port, _) = split_host_port(tail)?;
            AddressRef::Domain { host, port }
        }
    };
    Ok(ParseState::Done((address, len)))
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

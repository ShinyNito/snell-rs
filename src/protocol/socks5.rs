//! Runtime-free SOCKS5 protocol helpers.
//!
//! This module intentionally does not depend on Tokio, async traits, or any
//! concrete buffer type. Runtime code should exact-read/write around these
//! helpers.
//!
//! Design constraints:
//! - TCP request parsing must not read-ahead into application payload.
//! - UDP parsing must expose payload ranges without copying.
//! - Address is shared with Snell/outbound code through `protocol::address`.
//! - Encoding writes into caller-provided buffers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;

use thiserror::Error;

use super::address::{Address, AddressRef};

pub const VERSION: u8 = 0x05;

pub const MAX_METHODS: usize = 255;
pub const MAX_DOMAIN_LEN: usize = 255;

/// ATYP + DOMAIN_LEN + DOMAIN(255) + PORT.
pub const MAX_ADDR_FIELD_LEN: usize = 1 + 1 + MAX_DOMAIN_LEN + 2;

/// VER + NMETHODS + METHODS.
pub const MAX_GREETING_LEN: usize = 2 + MAX_METHODS;

/// VER + CMD + RSV + ADDR.
pub const MAX_REQUEST_LEN: usize = 3 + MAX_ADDR_FIELD_LEN;

/// VER + REP + RSV + ADDR.
pub const MAX_REPLY_LEN: usize = 3 + MAX_ADDR_FIELD_LEN;

/// RSV(2) + FRAG + ADDR.
pub const MAX_UDP_HEADER_LEN: usize = 3 + MAX_ADDR_FIELD_LEN;

/// RFC1929: VER + ULEN + UNAME(255) + PLEN + PASSWD(255).
pub const MAX_USERPASS_REQUEST_LEN: usize = 1 + 1 + 255 + 1 + 255;

pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_GSSAPI: u8 = 0x01;
pub const METHOD_USERNAME_PASSWORD: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xff;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Socks5Error {
    #[error("invalid SOCKS version: {0:#x}")]
    InvalidVersion(u8),
    #[error("invalid SOCKS reserved byte: {0:#x}")]
    InvalidReserved(u8),
    #[error("invalid SOCKS address type: {0:#x}")]
    InvalidAddressType(u8),
    #[error("invalid SOCKS domain name")]
    InvalidDomainName,
    #[error("empty SOCKS domain name")]
    EmptyDomainName,
    #[error("SOCKS domain name too long: {0}")]
    DomainTooLong(usize),
    #[error("buffer too small: needed {needed}, available {available}")]
    BufferTooSmall { needed: usize, available: usize },
    #[error("no acceptable SOCKS authentication method")]
    NoAcceptableMethod,
    #[error("SOCKS username too long: {0}")]
    UsernameTooLong(usize),
    #[error("SOCKS password too long: {0}")]
    PasswordTooLong(usize),
    #[error("malformed SOCKS packet: {0}")]
    Malformed(&'static str),
}

impl From<Socks5Error> for io::Error {
    fn from(value: Socks5Error) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, value)
    }
}

/// Exact-read friendly parse state, re-exported from [`crate::protocol`].
///
/// See [`crate::protocol::ParseState`] for the shared definition. Each codec
/// binds it to its own error type via a `ParseResult<T>` alias — here that is
/// `Result<ParseState<T>, Socks5Error>`.
pub use crate::protocol::ParseState;

/// Codec-specific parse result: the shared [`ParseState`] carrying either a
/// parsed SOCKS5 object or a [`Socks5Error`].
pub type ParseResult<T> = Result<ParseState<T>, Socks5Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Other(u8),
}

impl Command {
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            CMD_CONNECT => Self::Connect,
            CMD_BIND => Self::Bind,
            CMD_UDP_ASSOCIATE => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }

    #[must_use]
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
    #[must_use]
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

    #[must_use]
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

    #[must_use]
    pub fn from_io_error(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset => {
                Self::GeneralFailure
            }
            io::ErrorKind::TimedOut => Self::TtlExpired,
            io::ErrorKind::NotFound => Self::HostUnreachable,
            io::ErrorKind::AddrNotAvailable => Self::AddressTypeNotSupported,
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
    #[must_use]
    pub fn supports(self, method: u8) -> bool {
        self.methods.contains(&method)
    }

    #[must_use]
    pub fn select_first_supported(self, preferred: &[u8]) -> u8 {
        preferred
            .iter()
            .copied()
            .find(|method| self.supports(*method))
            .unwrap_or(METHOD_NO_ACCEPTABLE)
    }

    #[must_use]
    pub fn select_no_auth(self) -> u8 {
        if self.supports(METHOD_NO_AUTH) {
            METHOD_NO_AUTH
        } else {
            METHOD_NO_ACCEPTABLE
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSelection {
    pub method: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestRef<'a> {
    pub command: Command,
    pub destination: AddressRef<'a>,

    /// Number of bytes consumed by the SOCKS5 request header.
    ///
    /// If the caller parses from a larger buffer, bytes after `header_len`
    /// belong to application payload and must be preserved.
    pub header_len: usize,
}

impl RequestRef<'_> {
    #[must_use]
    pub fn into_owned(self) -> Request {
        Request {
            command: self.command,
            destination: self.destination.into_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub destination: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyRef<'a> {
    pub reply: Reply,
    pub bind: AddressRef<'a>,
    pub header_len: usize,
}

impl ReplyRef<'_> {
    #[must_use]
    pub fn into_owned(self) -> ReplyMessage {
        ReplyMessage {
            reply: self.reply,
            bind: self.bind.into_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyMessage {
    pub reply: Reply,
    pub bind: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPassRequestRef<'a> {
    pub username: &'a [u8],
    pub password: &'a [u8],
    pub consumed_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPassStatus {
    pub success: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketRef<'a> {
    pub frag: u8,
    pub destination: AddressRef<'a>,

    /// Length of `RSV RSV FRAG ATYP DST.ADDR DST.PORT`.
    ///
    /// For `PacketSlot`, this is the amount to strip before forwarding payload.
    pub header_len: usize,

    /// Same as `header_len`, kept explicit for call-sites that speak in terms
    /// of payload offsets.
    pub payload_offset: usize,

    pub payload: &'a [u8],
}

/// Parse SOCKS5 client greeting.
///
/// Layout:
/// `VER NMETHODS METHODS...`
pub fn greeting_need(buf: &[u8]) -> ParseResult<GreetingRef<'_>> {
    if buf.len() < 2 {
        return Ok(ParseState::Need(2));
    }

    if buf[0] != VERSION {
        return Err(Socks5Error::InvalidVersion(buf[0]));
    }

    let nmethods = usize::from(buf[1]);

    if nmethods == 0 {
        return Err(Socks5Error::Malformed("empty method list"));
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

/// Encode client greeting.
///
/// Useful for SOCKS5 outbound.
pub fn encode_greeting(dst: &mut [u8], methods: &[u8]) -> Result<usize, Socks5Error> {
    if methods.is_empty() {
        return Err(Socks5Error::Malformed("empty method list"));
    }

    if methods.len() > MAX_METHODS {
        return Err(Socks5Error::Malformed("too many methods"));
    }

    let needed = 2 + methods.len();
    ensure_capacity(dst, needed)?;

    dst[0] = VERSION;
    dst[1] = methods.len() as u8;
    dst[2..needed].copy_from_slice(methods);

    Ok(needed)
}

/// Encode the common no-auth client greeting:
/// `[0x05, 0x01, 0x00]`.
pub fn encode_no_auth_greeting(dst: &mut [u8]) -> Result<usize, Socks5Error> {
    encode_greeting(dst, &[METHOD_NO_AUTH])
}

/// Encode server method selection:
/// `[VER, METHOD]`.
pub fn encode_method_selection(dst: &mut [u8], method: u8) -> Result<usize, Socks5Error> {
    ensure_capacity(dst, 2)?;

    dst[0] = VERSION;
    dst[1] = method;

    Ok(2)
}

/// Parse server method selection.
///
/// Useful for SOCKS5 outbound.
pub fn method_selection_need(buf: &[u8]) -> ParseResult<MethodSelection> {
    if buf.len() < 2 {
        return Ok(ParseState::Need(2));
    }

    if buf[0] != VERSION {
        return Err(Socks5Error::InvalidVersion(buf[0]));
    }

    Ok(ParseState::Done(MethodSelection { method: buf[1] }))
}

/// Parse SOCKS5 request.
///
/// Layout:
/// `VER CMD RSV ATYP DST.ADDR DST.PORT`
pub fn request_need(buf: &[u8]) -> ParseResult<RequestRef<'_>> {
    if buf.len() < 4 {
        return Ok(ParseState::Need(4));
    }

    if buf[0] != VERSION {
        return Err(Socks5Error::InvalidVersion(buf[0]));
    }

    if buf[2] != 0 {
        return Err(Socks5Error::InvalidReserved(buf[2]));
    }

    let Some(addr_len) = addr_field_len_need(&buf[3..])? else {
        return Ok(ParseState::Need(addr_minimum_total(buf[3])));
    };

    let total = 3 + addr_len;

    if buf.len() < total {
        return Ok(ParseState::Need(total));
    }

    let (destination, consumed) = parse_addr_field(&buf[3..])?;
    debug_assert_eq!(addr_len, consumed);

    Ok(ParseState::Done(RequestRef {
        command: Command::from_u8(buf[1]),
        destination,
        header_len: total,
    }))
}

/// Encode SOCKS5 request.
///
/// Useful for SOCKS5 outbound CONNECT / UDP ASSOCIATE.
pub fn encode_request(
    dst: &mut [u8],
    command: Command,
    destination: AddressRef<'_>,
) -> Result<usize, Socks5Error> {
    let addr_len = encoded_addr_field_len(destination)?;
    let needed = 3 + addr_len;

    ensure_capacity(dst, needed)?;

    dst[0] = VERSION;
    dst[1] = command.to_u8();
    dst[2] = 0;

    let n = encode_addr_field(&mut dst[3..], destination)?;
    debug_assert_eq!(n, addr_len);

    Ok(needed)
}

/// Parse SOCKS5 reply.
///
/// Layout:
/// `VER REP RSV ATYP BND.ADDR BND.PORT`
pub fn reply_need(buf: &[u8]) -> ParseResult<ReplyRef<'_>> {
    if buf.len() < 4 {
        return Ok(ParseState::Need(4));
    }

    if buf[0] != VERSION {
        return Err(Socks5Error::InvalidVersion(buf[0]));
    }

    if buf[2] != 0 {
        return Err(Socks5Error::InvalidReserved(buf[2]));
    }

    let Some(addr_len) = addr_field_len_need(&buf[3..])? else {
        return Ok(ParseState::Need(addr_minimum_total(buf[3])));
    };

    let total = 3 + addr_len;

    if buf.len() < total {
        return Ok(ParseState::Need(total));
    }

    let (bind, consumed) = parse_addr_field(&buf[3..])?;
    debug_assert_eq!(addr_len, consumed);

    Ok(ParseState::Done(ReplyRef {
        reply: Reply::from_u8(buf[1]),
        bind,
        header_len: total,
    }))
}

/// Encode SOCKS5 reply.
///
/// Layout:
/// `VER REP RSV ATYP BND.ADDR BND.PORT`
pub fn encode_reply(
    dst: &mut [u8],
    reply: Reply,
    bind: AddressRef<'_>,
) -> Result<usize, Socks5Error> {
    let addr_len = encoded_addr_field_len(bind)?;
    let needed = 3 + addr_len;

    ensure_capacity(dst, needed)?;

    dst[0] = VERSION;
    dst[1] = reply.to_u8();
    dst[2] = 0;

    let n = encode_addr_field(&mut dst[3..], bind)?;
    debug_assert_eq!(n, addr_len);

    Ok(needed)
}

/// Common SOCKS5 bind address for replies.
///
/// Many proxies return `0.0.0.0:0` when the exact bind address is irrelevant.
#[must_use]
pub fn unspecified_ipv4_bind() -> AddressRef<'static> {
    AddressRef::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

/// RFC1929 username/password auth request parser.
///
/// Layout:
/// `VER ULEN UNAME PLEN PASSWD`, where VER is `0x01`.
pub fn userpass_request_need(buf: &[u8]) -> ParseResult<UserPassRequestRef<'_>> {
    if buf.len() < 2 {
        return Ok(ParseState::Need(2));
    }

    if buf[0] != 0x01 {
        return Err(Socks5Error::InvalidVersion(buf[0]));
    }

    let ulen = usize::from(buf[1]);
    let need_password_len_pos = 2 + ulen;

    if buf.len() < need_password_len_pos + 1 {
        return Ok(ParseState::Need(need_password_len_pos + 1));
    }

    let plen = usize::from(buf[need_password_len_pos]);
    let total = need_password_len_pos + 1 + plen;

    if buf.len() < total {
        return Ok(ParseState::Need(total));
    }

    Ok(ParseState::Done(UserPassRequestRef {
        username: &buf[2..2 + ulen],
        password: &buf[need_password_len_pos + 1..total],
        consumed_len: total,
    }))
}

/// Encode RFC1929 username/password auth request.
///
/// Useful for SOCKS5 outbound with auth.
pub fn encode_userpass_request(
    dst: &mut [u8],
    username: &[u8],
    password: &[u8],
) -> Result<usize, Socks5Error> {
    if username.len() > u8::MAX as usize {
        return Err(Socks5Error::UsernameTooLong(username.len()));
    }

    if password.len() > u8::MAX as usize {
        return Err(Socks5Error::PasswordTooLong(password.len()));
    }

    let needed = 1 + 1 + username.len() + 1 + password.len();
    ensure_capacity(dst, needed)?;

    dst[0] = 0x01;
    dst[1] = username.len() as u8;

    let user_start = 2;
    let user_end = user_start + username.len();

    dst[user_start..user_end].copy_from_slice(username);
    dst[user_end] = password.len() as u8;
    dst[user_end + 1..needed].copy_from_slice(password);

    Ok(needed)
}

/// Encode RFC1929 username/password auth response.
///
/// `status = 0` means success; non-zero means failure.
pub fn encode_userpass_response(dst: &mut [u8], success: bool) -> Result<usize, Socks5Error> {
    ensure_capacity(dst, 2)?;

    dst[0] = 0x01;
    dst[1] = u8::from(!success);

    Ok(2)
}

/// Parse RFC1929 username/password auth response.
///
/// Useful for SOCKS5 outbound with auth.
pub fn userpass_response_need(buf: &[u8]) -> ParseResult<UserPassStatus> {
    if buf.len() < 2 {
        return Ok(ParseState::Need(2));
    }

    if buf[0] != 0x01 {
        return Err(Socks5Error::InvalidVersion(buf[0]));
    }

    Ok(ParseState::Done(UserPassStatus {
        success: buf[1] == 0,
    }))
}

/// Parse SOCKS5 UDP datagram without copying payload.
///
/// Layout:
/// `RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA`
pub fn parse_udp_packet(buf: &[u8]) -> Result<UdpPacketRef<'_>, Socks5Error> {
    if buf.len() < 4 {
        return Err(Socks5Error::Malformed("UDP packet too short"));
    }

    if buf[0] != 0 || buf[1] != 0 {
        return Err(Socks5Error::InvalidReserved(if buf[0] != 0 {
            buf[0]
        } else {
            buf[1]
        }));
    }

    let frag = buf[2];
    let (destination, addr_len) = parse_addr_field(&buf[3..])?;
    let header_len = 3 + addr_len;

    if buf.len() < header_len {
        return Err(Socks5Error::Malformed("truncated UDP header"));
    }

    Ok(UdpPacketRef {
        frag,
        destination,
        header_len,
        payload_offset: header_len,
        payload: &buf[header_len..],
    })
}

/// Encode SOCKS5 UDP header into `dst`.
///
/// Writes:
/// `RSV RSV FRAG ATYP DST.ADDR DST.PORT`.
///
/// For a `PacketSlot`, call `slot.prepend(len)` first, then encode into the
/// returned prefix slice.
pub fn encode_udp_header(
    dst: &mut [u8],
    frag: u8,
    destination: AddressRef<'_>,
) -> Result<usize, Socks5Error> {
    let addr_len = encoded_addr_field_len(destination)?;
    let needed = 3 + addr_len;

    ensure_capacity(dst, needed)?;

    dst[0] = 0;
    dst[1] = 0;
    dst[2] = frag;

    let n = encode_addr_field(&mut dst[3..], destination)?;
    debug_assert_eq!(n, addr_len);

    Ok(needed)
}

/// Return the encoded SOCKS5 UDP header length without writing.
pub fn udp_header_len(destination: AddressRef<'_>) -> Result<usize, Socks5Error> {
    Ok(3 + encoded_addr_field_len(destination)?)
}

/// Encode SOCKS5 address field:
/// `ATYP ADDR PORT`.
pub fn encode_addr_field(dst: &mut [u8], address: AddressRef<'_>) -> Result<usize, Socks5Error> {
    match address {
        AddressRef::Ip(addr) => match addr {
            SocketAddr::V4(v4) => {
                let needed = 1 + 4 + 2;
                ensure_capacity(dst, needed)?;

                dst[0] = ATYP_IPV4;
                dst[1..5].copy_from_slice(&v4.ip().octets());
                dst[5..7].copy_from_slice(&v4.port().to_be_bytes());

                Ok(needed)
            }

            SocketAddr::V6(v6) => {
                let needed = 1 + 16 + 2;
                ensure_capacity(dst, needed)?;

                dst[0] = ATYP_IPV6;
                dst[1..17].copy_from_slice(&v6.ip().octets());
                dst[17..19].copy_from_slice(&v6.port().to_be_bytes());

                Ok(needed)
            }
        },

        AddressRef::Domain { host, port } => {
            let host_bytes = host.as_bytes();

            if host_bytes.is_empty() {
                return Err(Socks5Error::EmptyDomainName);
            }

            if host_bytes.len() > MAX_DOMAIN_LEN {
                return Err(Socks5Error::DomainTooLong(host_bytes.len()));
            }

            let needed = 1 + 1 + host_bytes.len() + 2;
            ensure_capacity(dst, needed)?;

            dst[0] = ATYP_DOMAIN;
            dst[1] = host_bytes.len() as u8;

            let host_start = 2;
            let host_end = host_start + host_bytes.len();

            dst[host_start..host_end].copy_from_slice(host_bytes);
            dst[host_end..host_end + 2].copy_from_slice(&port.to_be_bytes());

            Ok(needed)
        }
    }
}

/// Parse SOCKS5 address field:
/// `ATYP ADDR PORT`.
///
/// Returns `(address, consumed_len)`.
pub fn parse_addr_field(buf: &[u8]) -> Result<(AddressRef<'_>, usize), Socks5Error> {
    if buf.is_empty() {
        return Err(Socks5Error::Malformed("missing address type"));
    }

    match buf[0] {
        ATYP_IPV4 => {
            let needed = 1 + 4 + 2;
            ensure_available(buf, needed, "truncated IPv4 address")?;

            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            let addr = SocketAddr::new(IpAddr::V4(ip), port);

            Ok((AddressRef::Ip(addr), needed))
        }

        ATYP_IPV6 => {
            let needed = 1 + 16 + 2;
            ensure_available(buf, needed, "truncated IPv6 address")?;

            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);

            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            let addr = SocketAddr::new(IpAddr::V6(ip), port);

            Ok((AddressRef::Ip(addr), needed))
        }

        ATYP_DOMAIN => {
            ensure_available(buf, 2, "missing domain length")?;

            let host_len = usize::from(buf[1]);

            if host_len == 0 {
                return Err(Socks5Error::EmptyDomainName);
            }

            let needed = 1 + 1 + host_len + 2;
            ensure_available(buf, needed, "truncated domain address")?;

            let host_start = 2;
            let host_end = host_start + host_len;

            let host = str::from_utf8(&buf[host_start..host_end])
                .map_err(|_| Socks5Error::InvalidDomainName)?;

            let port = u16::from_be_bytes([buf[host_end], buf[host_end + 1]]);

            Ok((AddressRef::Domain { host, port }, needed))
        }

        other => Err(Socks5Error::InvalidAddressType(other)),
    }
}

/// Return encoded SOCKS5 address field length without writing.
pub fn encoded_addr_field_len(address: AddressRef<'_>) -> Result<usize, Socks5Error> {
    match address {
        AddressRef::Ip(SocketAddr::V4(_)) => Ok(1 + 4 + 2),
        AddressRef::Ip(SocketAddr::V6(_)) => Ok(1 + 16 + 2),
        AddressRef::Domain { host, .. } => {
            let len = host.len();

            if len == 0 {
                return Err(Socks5Error::EmptyDomainName);
            }

            if len > MAX_DOMAIN_LEN {
                return Err(Socks5Error::DomainTooLong(len));
            }

            Ok(1 + 1 + len + 2)
        }
    }
}

/// If enough bytes are present to know the full address field length, return it.
/// Otherwise return `Ok(None)`.
fn addr_field_len_need(buf: &[u8]) -> Result<Option<usize>, Socks5Error> {
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
                return Err(Socks5Error::EmptyDomainName);
            }

            Ok(Some(1 + 1 + len + 2))
        }
        other => Err(Socks5Error::InvalidAddressType(other)),
    }
}

fn addr_minimum_total(atyp: u8) -> usize {
    match atyp {
        ATYP_DOMAIN => 5, // VER/CMD/RSV/ATYP/LEN or VER/REP/RSV/ATYP/LEN
        _ => 4,
    }
}

fn ensure_capacity(dst: &[u8], needed: usize) -> Result<(), Socks5Error> {
    if dst.len() < needed {
        return Err(Socks5Error::BufferTooSmall {
            needed,
            available: dst.len(),
        });
    }

    Ok(())
}

fn ensure_available(src: &[u8], needed: usize, what: &'static str) -> Result<(), Socks5Error> {
    if src.len() < needed {
        return Err(Socks5Error::Malformed(what));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_selects_no_auth() {
        let buf = [VERSION, 2, METHOD_USERNAME_PASSWORD, METHOD_NO_AUTH];

        let ParseState::Done(greeting) = greeting_need(&buf).unwrap() else {
            panic!("expected greeting");
        };

        assert!(greeting.supports(METHOD_NO_AUTH));
        assert_eq!(greeting.select_no_auth(), METHOD_NO_AUTH);
        assert_eq!(greeting.consumed_len, 4);
    }

    #[test]
    fn encode_and_parse_connect_domain_request() {
        let mut buf = [0u8; MAX_REQUEST_LEN];

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
            panic!("expected request");
        };

        assert_eq!(req.command, Command::Connect);
        assert_eq!(
            req.destination,
            AddressRef::Domain {
                host: "example.com",
                port: 443
            }
        );
        assert_eq!(req.header_len, n);
    }

    #[test]
    fn request_need_total_for_partial_domain() {
        let partial = [VERSION, CMD_CONNECT, 0, ATYP_DOMAIN, 11];

        let ParseState::Need(total) = request_need(&partial).unwrap() else {
            panic!("expected need");
        };

        assert_eq!(total, 3 + 1 + 1 + 11 + 2);
    }

    #[test]
    fn encode_and_parse_ipv4_reply() {
        let bind = SocketAddr::from(([127, 0, 0, 1], 1080));
        let mut buf = [0u8; MAX_REPLY_LEN];

        let n = encode_reply(&mut buf, Reply::Succeeded, AddressRef::Ip(bind)).unwrap();

        let ParseState::Done(reply) = reply_need(&buf[..n]).unwrap() else {
            panic!("expected reply");
        };

        assert_eq!(reply.reply, Reply::Succeeded);
        assert_eq!(reply.bind, AddressRef::Ip(bind));
        assert_eq!(reply.header_len, n);
    }

    #[test]
    fn udp_packet_payload_is_borrowed() {
        let dst = SocketAddr::from(([1, 1, 1, 1], 53));
        let mut buf = [0u8; MAX_UDP_HEADER_LEN + 5];

        let header_len = encode_udp_header(&mut buf, 0, AddressRef::Ip(dst)).unwrap();
        buf[header_len..header_len + 5].copy_from_slice(b"hello");

        let pkt = parse_udp_packet(&buf[..header_len + 5]).unwrap();

        assert_eq!(pkt.frag, 0);
        assert_eq!(pkt.destination, AddressRef::Ip(dst));
        assert_eq!(pkt.header_len, header_len);
        assert_eq!(pkt.payload_offset, header_len);
        assert_eq!(pkt.payload, b"hello");
    }

    #[test]
    fn userpass_round_trip() {
        let mut buf = [0u8; MAX_USERPASS_REQUEST_LEN];

        let n = encode_userpass_request(&mut buf, b"user", b"pass").unwrap();

        let ParseState::Done(req) = userpass_request_need(&buf[..n]).unwrap() else {
            panic!("expected userpass request");
        };

        assert_eq!(req.username, b"user");
        assert_eq!(req.password, b"pass");
        assert_eq!(req.consumed_len, n);
    }

    #[test]
    fn method_selection_round_trip() {
        let mut buf = [0u8; 2];

        let n = encode_method_selection(&mut buf, METHOD_NO_AUTH).unwrap();

        let ParseState::Done(sel) = method_selection_need(&buf[..n]).unwrap() else {
            panic!("expected method selection");
        };

        assert_eq!(sel.method, METHOD_NO_AUTH);
    }
}

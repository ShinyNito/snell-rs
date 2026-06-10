use std::io::ErrorKind;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct Argon2Error(pub argon2::Error);

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid protocol version {0}")]
    InvalidProtocolVersion(u8),
    #[error("unknown command {0}")]
    UnknownCommand(u8),
    #[error("request is truncated")]
    TruncatedRequest,
    #[error("server reply is truncated")]
    TruncatedServerReply,
    #[error("invalid server reply")]
    InvalidServerReply,
    #[error("invalid client request")]
    InvalidClientRequest,
    #[error("server error {code}: {message}")]
    Server { code: u8, message: String },
    #[error("config error: {0}")]
    Config(String),
    #[error("host is empty")]
    EmptyHost,
    #[error("host is too long")]
    HostTooLong,
    #[error("invalid address type")]
    InvalidAddressType,
    #[error("ipv6 is disabled")]
    Ipv6Disabled,
    #[error("invalid domain name")]
    InvalidDomain(#[from] std::str::Utf8Error),
    #[error("invalid udp packet")]
    InvalidUdpPacket,
    #[error("invalid socks5 request")]
    InvalidSocksRequest,
    #[error("invalid socks5 response")]
    InvalidSocksResponse,
    #[error("socks5 proxy accepted no authentication methods")]
    Socks5NoAcceptableAuthMethod,
    #[error("socks5 proxy selected unsupported authentication method {0}")]
    UnsupportedSocks5AuthMethod(u8),
    #[error("socks5 proxy returned reply {0}")]
    Socks5Reply(u8),
    #[error("truncated udp packet")]
    TruncatedUdpPacket,
    #[error("payload is too large")]
    PayloadTooLarge,
    #[error("frame is too short")]
    FrameTooShort,
    #[error("frame length mismatch")]
    FrameLengthMismatch,
    #[error("invalid v4 frame header")]
    InvalidV4Header,
    #[error("zero chunk")]
    ZeroChunk,
    #[error("zero chunk with padding")]
    ZeroChunkWithPadding,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("write side is closed")]
    WriteClosed,
    #[error("short udp datagram write: sent {sent} of {expected} bytes")]
    ShortUdpWrite { sent: usize, expected: usize },
    #[error("{0} timed out")]
    Timeout(&'static str),
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("blocking task failed: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
    #[error("random source failed")]
    Random,
    #[error("argon2 failed: {0}")]
    Argon2(#[from] Argon2Error),
}

impl Error {
    pub fn is_closed_io(&self) -> bool {
        matches!(
            self,
            Self::Io(io) if Self::is_closed_io_kind(io.kind())
        )
    }

    pub fn is_invalid_udp_packet(&self) -> bool {
        matches!(
            self,
            Self::InvalidUdpPacket
                | Self::TruncatedUdpPacket
                | Self::InvalidAddressType
                | Self::InvalidDomain(_)
        )
    }

    pub fn is_closed_io_kind(kind: std::io::ErrorKind) -> bool {
        matches!(
            kind,
            ErrorKind::BrokenPipe
                | ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionReset
                | ErrorKind::NotConnected
                | ErrorKind::UnexpectedEof
        )
    }
}

impl From<argon2::Error> for Error {
    fn from(error: argon2::Error) -> Self {
        Self::Argon2(Argon2Error(error))
    }
}

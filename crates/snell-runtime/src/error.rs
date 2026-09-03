use std::io;

use snell_protocol::Error as ProtocolError;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("tcp connect timed out")]
    ConnectTimeout,
    #[error("cancelled")]
    Cancelled,
    #[error("udp association limit reached")]
    UdpLimit,
    #[error("v6-unsafe-raw is not enabled")]
    UnsafeRawDisabled,
    #[error("reuse idle timed out")]
    ReuseIdleTimeout,
    #[error("early payload exceeds 64 KiB")]
    EarlyPayloadTooLarge,
    #[error("duplicate v6 salt")]
    ReplayDuplicate,
    #[error("auto-detect matched more than one candidate")]
    AmbiguousProtocol,
    #[error("kdf queue is full")]
    KdfQueueFull,
    #[error("aead authentication failed")]
    Aead,
    #[error("socks5 has no acceptable method")]
    NoAcceptableMethod,
    #[error("socks5 command is not supported")]
    CommandNotSupported,
    #[error("server reject code {code}")]
    ServerReject { code: u8 },
    #[error(transparent)]
    Protocol(ProtocolError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<ProtocolError> for SessionError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::Aead => Self::Aead,
            other => Self::Protocol(other),
        }
    }
}

impl SessionError {
    pub fn from_timeout(kind: TimeoutKind) -> Self {
        match kind {
            TimeoutKind::Handshake => Self::HandshakeTimeout,
            TimeoutKind::Connect => Self::ConnectTimeout,
        }
    }

    pub fn is_stale_pool_error(&self) -> bool {
        match self {
            Self::HandshakeTimeout | Self::ConnectTimeout | Self::ReuseIdleTimeout => true,
            Self::Io(error) => is_stale_io(error.kind()),
            _ => false,
        }
    }
}

pub(crate) fn is_stale_io(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutKind {
    Handshake,
    Connect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectionEnd {
    CleanEof,
    ProtocolEnd,
    Cancelled,
    Failed,
}

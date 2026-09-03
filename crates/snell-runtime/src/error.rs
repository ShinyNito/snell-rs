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
    #[error("reuse is not implemented")]
    ReuseNotImplemented,
    #[error("udp is not implemented")]
    UdpNotImplemented,
    #[error("auto-detect is not implemented")]
    AutoNotImplemented,
    #[error("v6-unsafe-raw is not enabled")]
    UnsafeRawDisabled,
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

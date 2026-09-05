use std::io;

use snell_protocol::Error as ProtocolError;

use crate::platform::PlatformError;

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
    #[error("{0}")]
    Unsupported(&'static str),
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

impl From<PlatformError> for SessionError {
    fn from(error: PlatformError) -> Self {
        match error {
            PlatformError::Unsupported(msg) => Self::Unsupported(msg),
            PlatformError::Io(error) => Self::Io(error),
        }
    }
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
    pub(crate) fn is_stale_pool_error(&self) -> bool {
        match self {
            Self::HandshakeTimeout | Self::ConnectTimeout | Self::ReuseIdleTimeout => true,
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut
            ),
            _ => false,
        }
    }

    pub(crate) fn is_peer_closed(&self) -> bool {
        matches!(self, Self::Cancelled) || self.is_stale_pool_error()
    }
}

impl From<tokio::time::error::Elapsed> for SessionError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::HandshakeTimeout
    }
}

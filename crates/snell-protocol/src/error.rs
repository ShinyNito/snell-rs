use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("truncated")]
    Truncated,
    #[error("invalid protocol version {0}")]
    InvalidVersion(u8),
    #[error("unknown command {0}")]
    UnknownCommand(u8),
    #[error("empty host")]
    EmptyHost,
    #[error("host too long")]
    HostTooLong,
    #[error("host contains NUL")]
    HostContainsNul,
    #[error("invalid utf-8 host")]
    InvalidHostUtf8,
    #[error("invalid address type {0}")]
    InvalidAddressType(u8),
    #[error("invalid record header")]
    InvalidHeader,
    #[error("zero chunk with padding")]
    ZeroChunkWithPadding,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("buffer too small: needed {needed}, available {available}")]
    BufferTooSmall { needed: usize, available: usize },
    #[error("invalid reserved byte {0}")]
    InvalidReserved(u8),
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("invalid psk length {0}")]
    InvalidPskLen(usize),
    #[error("kdf failed")]
    Kdf,
    #[error("entropy exhausted")]
    EntropyExhausted,
    #[error("entropy unavailable")]
    Entropy,
    #[error("aead authentication failed")]
    Aead,
    #[error("pending wire not fully written")]
    PendingWire,
    #[error("plaintext not drained")]
    PlaintextNotDrained,
    #[error("encoder poisoned")]
    Poisoned,
}

pub type Result<T> = core::result::Result<T, Error>;

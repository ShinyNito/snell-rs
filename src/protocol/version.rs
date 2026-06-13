use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ProtocolVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
}

pub const DEFAULT_CLIENT_VERSION: ProtocolVersion = ProtocolVersion::V4;

impl ProtocolVersion {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
        }
    }

    pub const fn supports_udp(self) -> bool {
        matches!(self, Self::V3 | Self::V4 | Self::V5 | Self::V6)
    }

    pub const fn uses_v6_frames(self) -> bool {
        matches!(self, Self::V6)
    }

    pub const fn uses_quic_proxy(self) -> bool {
        matches!(self, Self::V5)
    }
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            6 => Ok(Self::V6),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

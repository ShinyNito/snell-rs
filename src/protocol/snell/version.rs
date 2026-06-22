/// Snell protocol version selected out of band.
///
/// In sing-snell, v5 reuses the v4 TCP record codec; it only adds QUIC proxy
/// behavior on the UDP side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// Snell v4: bare salt + AES-128-GCM records with first-record padding.
    V4,
    /// Snell v5: same record codec as v4.
    V5,
    V6(V6Mode),
}

impl ProtocolVersion {
    /// Parse an explicit protocol version name.
    ///
    /// # Errors
    /// Returns [`VersionParseError::UnknownVersion`] for unrecognized names.
    pub fn parse(s: &str) -> Result<Self, VersionParseError> {
        match s.to_ascii_lowercase().as_str() {
            "v4" => Ok(Self::V4),
            "v5" => Ok(Self::V5),
            "v6-default" => Ok(Self::V6(V6Mode::Default)),
            "v6-unshaped" => Ok(Self::V6(V6Mode::Unshaped)),
            "v6-unsafe-raw" => Ok(Self::V6(V6Mode::UnsafeRaw)),
            _ => Err(VersionParseError::UnknownVersion),
        }
    }
}

/// Snell v6 mode. v4/v5 do not have this dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V6Mode {
    /// v6 default mode: shaped profile framing.
    Default,
    /// v6 unshaped mode: bare-salt AES-GCM records without shaping.
    Unshaped,
    /// v6 unsafe-raw mode: plaintext 7-byte framing without crypto.
    UnsafeRaw,
}

/// Protocol version parsing error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VersionParseError {
    /// The string is not one of the known version names.
    #[error("unknown protocol version")]
    UnknownVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_requires_versioned_names() {
        assert_eq!(ProtocolVersion::parse("V4"), Ok(ProtocolVersion::V4));
        assert_eq!(ProtocolVersion::parse("V5"), Ok(ProtocolVersion::V5));
        assert_eq!(
            ProtocolVersion::parse("V6-DEFAULT"),
            Ok(ProtocolVersion::V6(V6Mode::Default))
        );
        assert_eq!(
            ProtocolVersion::parse("V6-UNSHAPED"),
            Ok(ProtocolVersion::V6(V6Mode::Unshaped))
        );
        assert_eq!(
            ProtocolVersion::parse("V6-UNSAFE-RAW"),
            Ok(ProtocolVersion::V6(V6Mode::UnsafeRaw))
        );
        assert_eq!(
            ProtocolVersion::parse("bogus"),
            Err(VersionParseError::UnknownVersion)
        );
        assert_eq!(
            ProtocolVersion::parse("default"),
            Err(VersionParseError::UnknownVersion)
        );
    }
}

//! Two-stage configuration: raw text → validated config.
//!
//! Unknown keys, unimplemented reuse/auto/UDP/unsafe-raw/tcp-brutal, and
//! missing required fields fail closed. PSK is stored as [`Psk`] so `Debug`
//! does not print the secret.

#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use snell_protocol::{PSK_MAX_LEN, PSK_MIN_LEN, Psk};

pub use snell_protocol as protocol;
pub use snell_protocol::ProtocolFlavor;

const CLIENT_SECTION: &str = "snell-client";
const SERVER_SECTION: &str = "snell-server";
const CLIENT_KEYS: &[&str] = &["listen", "server", "psk", "version", "reuse"];
const SERVER_KEYS: &[&str] = &[
    "listen",
    "psk",
    "version",
    "mode",
    "upstream_socks5",
    "tcp_brutal",
    "tcp_brutal_send_mbps",
    "tcp_brutal_cwnd_gain",
];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid INI: {0}")]
    Ini(&'static str),
    #[error("missing [{0}] section")]
    MissingSection(&'static str),
    #[error("missing {section}.{key}")]
    MissingKey {
        section: &'static str,
        key: &'static str,
    },
    #[error("invalid {section}.{key}: {msg}")]
    Invalid {
        section: &'static str,
        key: &'static str,
        msg: String,
    },
    #[error("unknown {section} key `{key}`")]
    UnknownKey { section: &'static str, key: String },
    #[error("{0}")]
    Unsupported(&'static str),
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Psk,
    pub version: ProtocolFlavor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outbound {
    Direct,
    Socks5 { server: SocketAddr },
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Psk,
    pub version: ProtocolFlavor,
    pub outbound: Outbound,
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let file = IniFile::parse(raw)?;
        let section = file
            .section(CLIENT_SECTION)
            .ok_or(ConfigError::MissingSection(CLIENT_SECTION))?;
        reject_unknown(CLIENT_SECTION, section, CLIENT_KEYS)?;

        let reuse = optional_bool(CLIENT_SECTION, section, "reuse")?.unwrap_or(false);
        if reuse {
            return Err(ConfigError::Unsupported(
                "client reuse is not implemented in this phase",
            ));
        }

        let version = parse_client_version(required(CLIENT_SECTION, section, "version")?)?;
        Ok(Self {
            listen: parse_socket(
                CLIENT_SECTION,
                "listen",
                required(CLIENT_SECTION, section, "listen")?,
            )?,
            server: parse_socket(
                CLIENT_SECTION,
                "server",
                required(CLIENT_SECTION, section, "server")?,
            )?,
            psk: parse_psk(CLIENT_SECTION, required(CLIENT_SECTION, section, "psk")?)?,
            version,
        })
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let file = IniFile::parse(raw)?;
        let section = file
            .section(SERVER_SECTION)
            .ok_or(ConfigError::MissingSection(SERVER_SECTION))?;
        reject_unknown(SERVER_SECTION, section, SERVER_KEYS)?;

        if optional_bool(SERVER_SECTION, section, "tcp_brutal")?.unwrap_or(false) {
            return Err(ConfigError::Unsupported(
                "tcp_brutal is not implemented in this phase",
            ));
        }
        if section.get("tcp_brutal_send_mbps").is_some()
            || section.get("tcp_brutal_cwnd_gain").is_some()
        {
            return Err(ConfigError::Unsupported(
                "tcp_brutal is not implemented in this phase",
            ));
        }

        let version = match section.get("version") {
            None => {
                return Err(ConfigError::Unsupported(
                    "server auto-detect is not implemented in this phase",
                ));
            }
            Some(version) => parse_server_version(version, section.get("mode"))?,
        };

        let outbound = match section.get("upstream_socks5") {
            None => Outbound::Direct,
            Some(value) => Outbound::Socks5 {
                server: parse_socket(SERVER_SECTION, "upstream_socks5", value)?,
            },
        };

        Ok(Self {
            listen: parse_socket(
                SERVER_SECTION,
                "listen",
                required(SERVER_SECTION, section, "listen")?,
            )?,
            psk: parse_psk(SERVER_SECTION, required(SERVER_SECTION, section, "psk")?)?,
            version,
            outbound,
        })
    }
}

pub fn parse_client_version(value: &str) -> Result<ProtocolFlavor, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "v4" => Ok(ProtocolFlavor::V4),
        "v5" => Ok(ProtocolFlavor::V5),
        "v6-default" => Ok(ProtocolFlavor::V6Shaped),
        "v6-unshaped" => Ok(ProtocolFlavor::V6Unshaped),
        "v6-unsafe-raw" => Err(ConfigError::Unsupported(
            "v6-unsafe-raw is not enabled in this phase",
        )),
        _ => Err(ConfigError::Invalid {
            section: CLIENT_SECTION,
            key: "version",
            msg: format!("unknown protocol version `{value}`"),
        }),
    }
}

pub fn parse_server_version(
    version: &str,
    mode: Option<&str>,
) -> Result<ProtocolFlavor, ConfigError> {
    let version = version.trim();
    let lowered = version.to_ascii_lowercase();
    if let Some(mode) = mode {
        if lowered != "6" {
            return Err(ConfigError::Invalid {
                section: SERVER_SECTION,
                key: "mode",
                msg: "mode is only valid when version = 6".to_owned(),
            });
        }
        let raw_mode = mode.trim();
        let mode = raw_mode.to_ascii_lowercase();
        return match mode.as_str() {
            "default" => Ok(ProtocolFlavor::V6Shaped),
            "unshaped" => Ok(ProtocolFlavor::V6Unshaped),
            "unsafe-raw" => Err(ConfigError::Unsupported(
                "v6-unsafe-raw is not enabled in this phase",
            )),
            _ => Err(ConfigError::Invalid {
                section: SERVER_SECTION,
                key: "mode",
                msg: format!("expected default or unshaped, got `{raw_mode}`"),
            }),
        };
    }
    match lowered.as_str() {
        "4" | "v4" => Ok(ProtocolFlavor::V4),
        "5" | "v5" => Ok(ProtocolFlavor::V5),
        "6" | "v6-default" => Ok(ProtocolFlavor::V6Shaped),
        "v6-unshaped" => Ok(ProtocolFlavor::V6Unshaped),
        "v6-unsafe-raw" => Err(ConfigError::Unsupported(
            "v6-unsafe-raw is not enabled in this phase",
        )),
        _ => Err(ConfigError::Invalid {
            section: SERVER_SECTION,
            key: "version",
            msg: format!("expected 4, 5, or 6, got `{version}`"),
        }),
    }
}

pub fn parse_psk_str(value: &str) -> Result<Psk, ConfigError> {
    parse_psk("cli", value)
}

fn parse_psk(section: &'static str, value: &str) -> Result<Psk, ConfigError> {
    Psk::new(value.as_bytes().to_vec()).map_err(|_| ConfigError::Invalid {
        section,
        key: "psk",
        msg: format!(
            "psk length {} is out of range ({}..={})",
            value.len(),
            PSK_MIN_LEN,
            PSK_MAX_LEN
        ),
    })
}

fn parse_socket(
    section: &'static str,
    key: &'static str,
    value: &str,
) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|_| ConfigError::Invalid {
        section,
        key,
        msg: format!("invalid socket address `{value}`"),
    })
}

fn required<'a>(
    section: &'static str,
    keys: &'a Section,
    key: &'static str,
) -> Result<&'a str, ConfigError> {
    keys.get(key)
        .ok_or(ConfigError::MissingKey { section, key })
}

fn optional_bool(
    section: &'static str,
    keys: &Section,
    key: &'static str,
) -> Result<Option<bool>, ConfigError> {
    let Some(value) = keys.get(key) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(Some(true)),
        "false" | "no" | "0" | "off" => Ok(Some(false)),
        _ => Err(ConfigError::Invalid {
            section,
            key,
            msg: format!("expected a boolean, got `{value}`"),
        }),
    }
}

fn reject_unknown(
    section: &'static str,
    keys: &Section,
    known: &[&str],
) -> Result<(), ConfigError> {
    for (key, _) in &keys.pairs {
        if !known.iter().any(|item| item.eq_ignore_ascii_case(key)) {
            return Err(ConfigError::UnknownKey {
                section,
                key: key.clone(),
            });
        }
    }
    Ok(())
}

struct IniFile {
    sections: Vec<(String, Section)>,
}

struct Section {
    pairs: Vec<(String, String)>,
}

impl Section {
    fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

impl IniFile {
    fn parse(raw: &str) -> Result<Self, ConfigError> {
        let mut sections = Vec::new();
        let mut current: Option<(String, Section)> = None;
        let mut seen = BTreeSet::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[') {
                let name = name
                    .strip_suffix(']')
                    .ok_or(ConfigError::Ini("unclosed section header"))?
                    .trim();
                if name.is_empty() {
                    return Err(ConfigError::Ini("empty section name"));
                }
                if !seen.insert(name.to_ascii_lowercase()) {
                    return Err(ConfigError::Ini("duplicate section"));
                }
                if let Some(prev) = current.take() {
                    sections.push(prev);
                }
                current = Some((name.to_owned(), Section { pairs: Vec::new() }));
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(ConfigError::Ini("expected key = value"));
            };
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                return Err(ConfigError::Ini("empty key"));
            }
            let Some((_, section)) = current.as_mut() else {
                return Err(ConfigError::Ini("key outside section"));
            };
            if section.get(key).is_some() {
                return Err(ConfigError::Ini("duplicate key"));
            }
            section.pairs.push((key.to_owned(), value.to_owned()));
        }
        if let Some(prev) = current.take() {
            sections.push(prev);
        }
        Ok(Self { sections })
    }

    fn section(&self, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, s)| s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: &str = "0123456789abcdef";

    #[test]
    fn client_ini_parses_exact_v4() {
        let cfg = ClientConfig::parse(&format!(
            "[snell-client]\nlisten = 127.0.0.1:1080\nserver = 127.0.0.1:8388\npsk = {PSK}\nversion = v4\nreuse = false\n"
        ))
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(cfg.version, ProtocolFlavor::V4);
        assert_eq!(format!("{:?}", cfg.psk), "Psk(redacted)");
    }

    #[test]
    fn client_reuse_fails_closed() {
        let err = ClientConfig::parse(&format!(
            "[snell-client]\nlisten = 127.0.0.1:1080\nserver = 127.0.0.1:8388\npsk = {PSK}\nversion = v4\nreuse = true\n"
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported(_)));
    }

    #[test]
    fn client_unsafe_raw_fails_closed() {
        let err = ClientConfig::parse(&format!(
            "[snell-client]\nlisten = 127.0.0.1:1080\nserver = 127.0.0.1:8388\npsk = {PSK}\nversion = v6-unsafe-raw\n"
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported(_)));
    }

    #[test]
    fn server_missing_version_fails_closed() {
        let err = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\n"
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported(_)));
    }

    #[test]
    fn server_v6_unshaped_mode() {
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 6\nmode = unshaped\n"
        ))
        .unwrap();
        assert_eq!(cfg.version, ProtocolFlavor::V6Unshaped);
        assert_eq!(cfg.outbound, Outbound::Direct);
    }

    #[test]
    fn server_mode_is_ascii_case_insensitive() {
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 6\nmode = Unshaped\n"
        ))
        .unwrap();
        assert_eq!(cfg.version, ProtocolFlavor::V6Unshaped);
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 6\nmode = DEFAULT\n"
        ))
        .unwrap();
        assert_eq!(cfg.version, ProtocolFlavor::V6Shaped);
    }

    #[test]
    fn server_socks5_outbound() {
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 4\nupstream_socks5 = 127.0.0.1:1081\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.outbound,
            Outbound::Socks5 {
                server: "127.0.0.1:1081".parse().unwrap()
            }
        );
    }

    #[test]
    fn server_tcp_brutal_fails_closed() {
        let err = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 4\ntcp_brutal = true\n"
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported(_)));
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = ClientConfig::parse(&format!(
            "[snell-client]\nlisten = 127.0.0.1:1080\nserver = 127.0.0.1:8388\npsk = {PSK}\nversion = v4\nobfs = http\n"
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownKey { .. }));
    }
}

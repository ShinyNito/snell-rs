//! Two-stage configuration: raw text → validated config.
//!
//! Unknown keys, unimplemented unsafe-raw, and missing required fields fail
//! closed. `tcp_brutal` is parsed and fail-closed if requested with invalid
//! parameters. `reuse = true` is allowed. Omitting server `version` selects
//! auto-detect. PSK is stored as [`Psk`] so `Debug` does not print the secret.
//! UDP ASSOCIATE is handled in `snell-runtime`.

#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use snell_protocol::{PSK_MAX_LEN, PSK_MIN_LEN, Psk};

pub use snell_protocol as protocol;
pub use snell_protocol::{ProtocolFlavor, ProtocolSelection};

const CLIENT_SECTION: &str = "snell-client";
const SERVER_SECTION: &str = "snell-server";
const TCP_BRUTAL_CWND_GAIN_MIN: u32 = 5;
const TCP_BRUTAL_CWND_GAIN_MAX: u32 = 80;
const TCP_BRUTAL_SEND_MBPS_MAX: u32 = 100_000;
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
    pub reuse: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outbound {
    Direct,
    Socks5 { server: SocketAddr },
}

/// Linux tcp-brutal request. Off by default. Runtime fail-closes if the OS cannot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBrutal {
    pub send_mbps: u32,
    pub cwnd_gain: u32,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Psk,
    pub selection: ProtocolSelection,
    pub outbound: Outbound,
    pub tcp_brutal: Option<TcpBrutal>,
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
            reuse,
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

        let tcp_brutal = parse_tcp_brutal(section)?;

        let selection = match section.get("version") {
            None => {
                if section.get("mode").is_some() {
                    return Err(ConfigError::Invalid {
                        section: SERVER_SECTION,
                        key: "mode",
                        msg: "mode is only valid when version = 6".to_owned(),
                    });
                }
                ProtocolSelection::Auto
            }
            Some(version) => {
                ProtocolSelection::Exact(parse_server_version(version, section.get("mode"))?)
            }
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
            selection,
            outbound,
            tcp_brutal,
        })
    }
}

fn parse_tcp_brutal(section: &Section) -> Result<Option<TcpBrutal>, ConfigError> {
    let enabled = optional_bool(SERVER_SECTION, section, "tcp_brutal")?.unwrap_or(false);
    let send = section.get("tcp_brutal_send_mbps");
    let gain = section.get("tcp_brutal_cwnd_gain");
    if !enabled {
        if send.is_some() || gain.is_some() {
            return Err(ConfigError::Invalid {
                section: SERVER_SECTION,
                key: "tcp_brutal",
                msg: "tcp_brutal_send_mbps/tcp_brutal_cwnd_gain require tcp_brutal = true"
                    .to_owned(),
            });
        }
        return Ok(None);
    }
    let send_mbps = parse_u32(
        SERVER_SECTION,
        "tcp_brutal_send_mbps",
        send.ok_or(ConfigError::MissingKey {
            section: SERVER_SECTION,
            key: "tcp_brutal_send_mbps",
        })?,
    )?;
    if send_mbps == 0 || send_mbps > TCP_BRUTAL_SEND_MBPS_MAX {
        return Err(ConfigError::Invalid {
            section: SERVER_SECTION,
            key: "tcp_brutal_send_mbps",
            msg: format!("expected 1..={TCP_BRUTAL_SEND_MBPS_MAX}, got `{send_mbps}`"),
        });
    }
    let cwnd_gain = parse_u32(
        SERVER_SECTION,
        "tcp_brutal_cwnd_gain",
        gain.ok_or(ConfigError::MissingKey {
            section: SERVER_SECTION,
            key: "tcp_brutal_cwnd_gain",
        })?,
    )?;
    if !(TCP_BRUTAL_CWND_GAIN_MIN..=TCP_BRUTAL_CWND_GAIN_MAX).contains(&cwnd_gain) {
        return Err(ConfigError::Invalid {
            section: SERVER_SECTION,
            key: "tcp_brutal_cwnd_gain",
            msg: format!(
                "expected {TCP_BRUTAL_CWND_GAIN_MIN}..={TCP_BRUTAL_CWND_GAIN_MAX}, got `{cwnd_gain}`"
            ),
        });
    }
    Ok(Some(TcpBrutal {
        send_mbps,
        cwnd_gain,
    }))
}

fn parse_u32(section: &'static str, key: &'static str, value: &str) -> Result<u32, ConfigError> {
    value.parse().map_err(|_| ConfigError::Invalid {
        section,
        key,
        msg: format!("expected a u32, got `{value}`"),
    })
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
        assert!(!cfg.reuse);
        assert_eq!(format!("{:?}", cfg.psk), "Psk(redacted)");
    }

    #[test]
    fn client_reuse_true_parses() {
        let cfg = ClientConfig::parse(&format!(
            "[snell-client]\nlisten = 127.0.0.1:1080\nserver = 127.0.0.1:8388\npsk = {PSK}\nversion = v4\nreuse = true\n"
        ))
        .unwrap();
        assert!(cfg.reuse);
        assert_eq!(cfg.version, ProtocolFlavor::V4);
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
    fn server_missing_version_is_auto() {
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\n"
        ))
        .unwrap();
        assert_eq!(cfg.selection, ProtocolSelection::Auto);
    }

    #[test]
    fn server_v6_unshaped_mode() {
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 6\nmode = unshaped\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.selection,
            ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped)
        );
        assert_eq!(cfg.outbound, Outbound::Direct);
    }

    #[test]
    fn server_mode_is_ascii_case_insensitive() {
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 6\nmode = Unshaped\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.selection,
            ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped)
        );
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 6\nmode = DEFAULT\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.selection,
            ProtocolSelection::Exact(ProtocolFlavor::V6Shaped)
        );
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
        assert!(matches!(
            err,
            ConfigError::MissingKey {
                key: "tcp_brutal_send_mbps",
                ..
            }
        ));
    }

    #[test]
    fn server_tcp_brutal_parses_when_complete() {
        let cfg = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 4\ntcp_brutal = true\ntcp_brutal_send_mbps = 100\ntcp_brutal_cwnd_gain = 15\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.tcp_brutal,
            Some(TcpBrutal {
                send_mbps: 100,
                cwnd_gain: 15
            })
        );
    }

    #[test]
    fn server_tcp_brutal_params_without_enable_fail() {
        let err = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 4\ntcp_brutal_send_mbps = 100\n"
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                key: "tcp_brutal",
                ..
            }
        ));
    }

    #[test]
    fn server_tcp_brutal_gain_out_of_range_fails() {
        let err = ServerConfig::parse(&format!(
            "[snell-server]\nlisten = 127.0.0.1:8388\npsk = {PSK}\nversion = 4\ntcp_brutal = true\ntcp_brutal_send_mbps = 100\ntcp_brutal_cwnd_gain = 4\n"
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                key: "tcp_brutal_cwnd_gain",
                ..
            }
        ));
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

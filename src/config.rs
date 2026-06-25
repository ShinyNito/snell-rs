use std::{fs, io, net::SocketAddr, path::Path};

use ini::Ini;
use thiserror::Error;

use crate::protocol::snell::{
    crypto::kdf::{PSK_MAX_LEN, PSK_MIN_LEN},
    version::{ProtocolVersion, V6Mode},
};

const SNELL_CLIENT_SECTION: &str = "snell-client";
const SNELL_SERVER_SECTION: &str = "snell-server";
const CLIENT_KNOWN_KEYS: &[&str] = &["listen", "server", "psk", "version", "reuse"];
const SERVER_KNOWN_KEYS: &[&str] = &[
    "listen",
    "psk",
    "version",
    "mode",
    "upstream_socks5",
    "tcp_brutal",
    "tcp_brutal_send_mbps",
    "tcp_brutal_cwnd_gain",
];
const TCP_BRUTAL_CWND_GAIN: u32 = 20;
const TCP_BRUTAL_SEND_MBIT_TO_BYTES: u64 = 125_000;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid INI in {path}: {source}")]
    Ini {
        path: String,
        #[source]
        source: ini::ParseError,
    },
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
}

impl From<ConfigError> for io::Error {
    fn from(value: ConfigError) -> Self {
        io::Error::other(value)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Vec<u8>,
    pub version: ProtocolVersion,
    pub reuse: bool,
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let ini = load_ini(path)?;
        Self::from_ini(&ini)
    }

    fn from_ini(ini: &Ini) -> Result<Self, ConfigError> {
        let section = ini
            .section(Some(SNELL_CLIENT_SECTION))
            .ok_or(ConfigError::MissingSection(SNELL_CLIENT_SECTION))?;
        report_unknown_keys(SNELL_CLIENT_SECTION, section, CLIENT_KNOWN_KEYS);
        reject_client_tcp_brutal(section)?;

        Ok(Self {
            listen: required_socket_addr(SNELL_CLIENT_SECTION, section, "listen")?,
            server: required_socket_addr(SNELL_CLIENT_SECTION, section, "server")?,
            psk: required_psk(SNELL_CLIENT_SECTION, section)?,
            version: required_version(SNELL_CLIENT_SECTION, section)?,
            reuse: optional_bool(SNELL_CLIENT_SECTION, section, "reuse")?.unwrap_or(false),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Vec<u8>,
    pub protocol: Option<ProtocolVersion>,
    pub upstream_socks5: Option<SocketAddr>,
    pub tcp_brutal: Option<TcpBrutalConfig>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpBrutalConfig {
    pub rate_bytes_per_sec: u64,
    pub cwnd_gain: u32,
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let ini = load_ini(path)?;
        Self::from_ini(&ini)
    }

    fn from_ini(ini: &Ini) -> Result<Self, ConfigError> {
        let section = ini
            .section(Some(SNELL_SERVER_SECTION))
            .ok_or(ConfigError::MissingSection(SNELL_SERVER_SECTION))?;
        report_unknown_keys(SNELL_SERVER_SECTION, section, SERVER_KNOWN_KEYS);

        Ok(Self {
            listen: required_socket_addr(SNELL_SERVER_SECTION, section, "listen")?,
            psk: required_psk(SNELL_SERVER_SECTION, section)?,
            protocol: optional_server_protocol(SNELL_SERVER_SECTION, section)?,
            upstream_socks5: optional_socket_addr(
                SNELL_SERVER_SECTION,
                section,
                "upstream_socks5",
            )?,
            tcp_brutal: optional_tcp_brutal(SNELL_SERVER_SECTION, section)?,
        })
    }
}

pub fn psk_from_str(value: &str) -> Result<Vec<u8>, ConfigError> {
    let bytes = value.as_bytes();
    if !(PSK_MIN_LEN..=PSK_MAX_LEN).contains(&bytes.len()) {
        return Err(ConfigError::Invalid {
            section: "cli",
            key: "psk",
            msg: format!(
                "psk length {} is out of range ({}..={})",
                bytes.len(),
                PSK_MIN_LEN,
                PSK_MAX_LEN
            ),
        });
    }
    Ok(bytes.to_vec())
}

fn load_ini(path: impl AsRef<Path>) -> Result<Ini, ConfigError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ini::load_from_str(&raw).map_err(|source| ConfigError::Ini {
        path: path.display().to_string(),
        source,
    })
}

fn report_unknown_keys(section_name: &str, section: &ini::Properties, known: &[&str]) {
    for (key, _) in section {
        if !known.iter().any(|known| known.eq_ignore_ascii_case(key)) {
            tracing::trace!(section = section_name, key, "ignoring unknown config key");
        }
    }
}

fn get_trimmed<'a>(section: &'a ini::Properties, key: &str) -> Option<&'a str> {
    section
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn required_socket_addr(
    section_name: &'static str,
    section: &ini::Properties,
    key: &'static str,
) -> Result<SocketAddr, ConfigError> {
    optional_socket_addr(section_name, section, key)?.ok_or(ConfigError::MissingKey {
        section: section_name,
        key,
    })
}

fn optional_socket_addr(
    section_name: &'static str,
    section: &ini::Properties,
    key: &'static str,
) -> Result<Option<SocketAddr>, ConfigError> {
    let Some(value) = get_trimmed(section, key) else {
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|error: std::net::AddrParseError| ConfigError::Invalid {
            section: section_name,
            key,
            msg: error.to_string(),
        })
}

fn required_psk(
    section_name: &'static str,
    section: &ini::Properties,
) -> Result<Vec<u8>, ConfigError> {
    let value = get_trimmed(section, "psk").ok_or(ConfigError::MissingKey {
        section: section_name,
        key: "psk",
    })?;
    psk_from_str(value).map_err(|error| match error {
        ConfigError::Invalid { msg, .. } => ConfigError::Invalid {
            section: section_name,
            key: "psk",
            msg,
        },
        other => other,
    })
}

fn required_version(
    section_name: &'static str,
    section: &ini::Properties,
) -> Result<ProtocolVersion, ConfigError> {
    let value = get_trimmed(section, "version").ok_or(ConfigError::MissingKey {
        section: section_name,
        key: "version",
    })?;
    ProtocolVersion::parse(value).map_err(|error| ConfigError::Invalid {
        section: section_name,
        key: "version",
        msg: error.to_string(),
    })
}

fn optional_server_protocol(
    section_name: &'static str,
    section: &ini::Properties,
) -> Result<Option<ProtocolVersion>, ConfigError> {
    server_protocol_from_parts(
        section_name,
        get_trimmed(section, "version"),
        get_trimmed(section, "mode"),
    )
}

pub fn server_protocol_from_cli(
    version: Option<&str>,
    mode: Option<&str>,
) -> Result<Option<ProtocolVersion>, ConfigError> {
    server_protocol_from_parts("cli", version, mode)
}

fn server_protocol_from_parts(
    section_name: &'static str,
    version: Option<&str>,
    mode: Option<&str>,
) -> Result<Option<ProtocolVersion>, ConfigError> {
    let Some(version) = version else {
        if mode.is_some() {
            return Err(ConfigError::Invalid {
                section: section_name,
                key: "mode",
                msg: "mode requires version = 6".to_owned(),
            });
        }
        return Ok(None);
    };

    if let Some(mode) = mode {
        if version != "6" {
            return Err(ConfigError::Invalid {
                section: section_name,
                key: "mode",
                msg: "mode is only valid when version = 6".to_owned(),
            });
        }
        return parse_v6_mode(mode)
            .map(|mode| Some(ProtocolVersion::V6(mode)))
            .ok_or_else(|| ConfigError::Invalid {
                section: section_name,
                key: "mode",
                msg: "expected default, unshaped, or unsafe-raw".to_owned(),
            });
    }

    parse_server_version(section_name, version).map(Some)
}

fn parse_server_version(
    section_name: &'static str,
    value: &str,
) -> Result<ProtocolVersion, ConfigError> {
    match value {
        "4" => Ok(ProtocolVersion::V4),
        "5" => Ok(ProtocolVersion::V5),
        "6" => Ok(ProtocolVersion::V6(V6Mode::Default)),
        _ => Err(ConfigError::Invalid {
            section: section_name,
            key: "version",
            msg: "expected 4, 5, or 6".to_owned(),
        }),
    }
}

fn parse_v6_mode(value: &str) -> Option<V6Mode> {
    match value {
        "default" => Some(V6Mode::Default),
        "unshaped" => Some(V6Mode::Unshaped),
        "unsafe-raw" => Some(V6Mode::UnsafeRaw),
        _ => None,
    }
}

fn optional_bool(
    section_name: &'static str,
    section: &ini::Properties,
    key: &'static str,
) -> Result<Option<bool>, ConfigError> {
    let Some(value) = get_trimmed(section, key) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(Some(true)),
        "false" | "no" | "0" | "off" => Ok(Some(false)),
        _ => Err(ConfigError::Invalid {
            section: section_name,
            key,
            msg: format!("expected a boolean, got `{value}`"),
        }),
    }
}

fn optional_u32(
    section_name: &'static str,
    section: &ini::Properties,
    key: &'static str,
) -> Result<Option<u32>, ConfigError> {
    let Some(value) = get_trimmed(section, key) else {
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|error: std::num::ParseIntError| ConfigError::Invalid {
            section: section_name,
            key,
            msg: error.to_string(),
        })
}

fn optional_u64(
    section_name: &'static str,
    section: &ini::Properties,
    key: &'static str,
) -> Result<Option<u64>, ConfigError> {
    let Some(value) = get_trimmed(section, key) else {
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|error: std::num::ParseIntError| ConfigError::Invalid {
            section: section_name,
            key,
            msg: error.to_string(),
        })
}

fn optional_tcp_brutal(
    section_name: &'static str,
    section: &ini::Properties,
) -> Result<Option<TcpBrutalConfig>, ConfigError> {
    if !optional_bool(section_name, section, "tcp_brutal")?.unwrap_or(false) {
        return Ok(None);
    }

    let send_mbps = optional_u64(section_name, section, "tcp_brutal_send_mbps")?.ok_or(
        ConfigError::MissingKey {
            section: section_name,
            key: "tcp_brutal_send_mbps",
        },
    )?;
    if send_mbps == 0 {
        return Err(ConfigError::Invalid {
            section: section_name,
            key: "tcp_brutal_send_mbps",
            msg: "must be greater than 0".to_owned(),
        });
    }
    let rate_bytes_per_sec =
        send_mbps
            .checked_mul(TCP_BRUTAL_SEND_MBIT_TO_BYTES)
            .ok_or(ConfigError::Invalid {
                section: section_name,
                key: "tcp_brutal_send_mbps",
                msg: "is too large".to_owned(),
            })?;

    let cwnd_gain = optional_u32(section_name, section, "tcp_brutal_cwnd_gain")?
        .unwrap_or(TCP_BRUTAL_CWND_GAIN);
    if cwnd_gain == 0 {
        return Err(ConfigError::Invalid {
            section: section_name,
            key: "tcp_brutal_cwnd_gain",
            msg: "must be greater than 0".to_owned(),
        });
    }

    Ok(Some(TcpBrutalConfig {
        rate_bytes_per_sec,
        cwnd_gain,
    }))
}

fn reject_client_tcp_brutal(section: &ini::Properties) -> Result<(), ConfigError> {
    for key in ["tcp_brutal", "tcp_brutal_send_mbps", "tcp_brutal_cwnd_gain"] {
        if section.contains_key(key) {
            return Err(ConfigError::Invalid {
                section: SNELL_CLIENT_SECTION,
                key,
                msg: "is only supported in [snell-server]".to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::snell::version::V6Mode;

    fn client_from(input: &str) -> Result<ClientConfig, ConfigError> {
        ClientConfig::from_ini(&Ini::load_from_str(input).unwrap())
    }

    fn server_from(input: &str) -> Result<ServerConfig, ConfigError> {
        ServerConfig::from_ini(&Ini::load_from_str(input).unwrap())
    }

    #[test]
    fn client_minimal() {
        let cfg = client_from(
            r#"
[snell-client]
listen = 127.0.0.1:1080
server = 1.2.3.4:8388
psk = testpsk-16-byte!
version = v6-default
"#,
        )
        .unwrap();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:1080");
        assert_eq!(cfg.server.to_string(), "1.2.3.4:8388");
        assert_eq!(cfg.psk, b"testpsk-16-byte!");
        assert_eq!(cfg.version, ProtocolVersion::V6(V6Mode::Default));
        assert!(!cfg.reuse);
    }

    #[test]
    fn client_reuse_variants() {
        for (literal, expected) in [
            ("true", true),
            ("yes", true),
            ("ON", true),
            ("1", true),
            ("false", false),
            ("no", false),
            ("Off", false),
            ("0", false),
        ] {
            let cfg = client_from(&format!(
                "[snell-client]\nlisten=127.0.0.1:1\nserver=1.1.1.1:1\npsk=testpsk-16-byte!\nversion=v4\nreuse={literal}\n"
            ))
            .unwrap();
            assert_eq!(cfg.reuse, expected, "literal {literal}");
        }
    }

    #[test]
    fn server_upstream_socks5() {
        let cfg = server_from(
            r#"
[snell-server]
listen = 0.0.0.0:8388
psk = testpsk-16-byte!
version = 4
upstream_socks5 = 127.0.0.1:1080
"#,
        )
        .unwrap();
        assert_eq!(cfg.listen.to_string(), "0.0.0.0:8388");
        assert_eq!(cfg.protocol, Some(ProtocolVersion::V4));
        assert_eq!(
            cfg.upstream_socks5.map(|addr| addr.to_string()),
            Some("127.0.0.1:1080".to_owned())
        );
    }

    #[test]
    fn server_version_is_optional_for_auto_probe() {
        let cfg = server_from(
            r#"
[snell-server]
listen = 0.0.0.0:8388
psk = testpsk-16-byte!
"#,
        )
        .unwrap();
        assert_eq!(cfg.protocol, None);
    }

    #[test]
    fn server_tcp_brutal_config() {
        let cfg = server_from(
            r#"
[snell-server]
listen = 0.0.0.0:8388
psk = testpsk-16-byte!
tcp_brutal = true
tcp_brutal_send_mbps = 100
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.tcp_brutal,
            Some(TcpBrutalConfig {
                rate_bytes_per_sec: 12_500_000,
                cwnd_gain: TCP_BRUTAL_CWND_GAIN,
            })
        );

        let cfg = server_from(
            r#"
[snell-server]
listen = 0.0.0.0:8388
psk = testpsk-16-byte!
tcp_brutal = true
tcp_brutal_send_mbps = 100
tcp_brutal_cwnd_gain = 42
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.tcp_brutal,
            Some(TcpBrutalConfig {
                rate_bytes_per_sec: 12_500_000,
                cwnd_gain: 42,
            })
        );
    }

    #[test]
    fn rejects_invalid_tcp_brutal_config() {
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\ntcp_brutal=true\n"
            ),
            Err(ConfigError::MissingKey {
                key: "tcp_brutal_send_mbps",
                ..
            })
        ));
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\ntcp_brutal=true\ntcp_brutal_send_mbps=0\n"
            ),
            Err(ConfigError::Invalid {
                key: "tcp_brutal_send_mbps",
                ..
            })
        ));
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\ntcp_brutal=true\ntcp_brutal_send_mbps=100\ntcp_brutal_cwnd_gain=0\n"
            ),
            Err(ConfigError::Invalid {
                key: "tcp_brutal_cwnd_gain",
                ..
            })
        ));
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\ntcp_brutal=true\ntcp_brutal_send_mbps=100\ntcp_brutal_cwnd_gain=fast\n"
            ),
            Err(ConfigError::Invalid {
                key: "tcp_brutal_cwnd_gain",
                ..
            })
        ));
        assert!(matches!(
            client_from(
                "[snell-client]\nlisten=127.0.0.1:1\nserver=1.1.1.1:1\npsk=testpsk-16-byte!\nversion=v4\ntcp_brutal=true\n"
            ),
            Err(ConfigError::Invalid {
                section: "snell-client",
                key: "tcp_brutal",
                ..
            })
        ));
    }

    #[test]
    fn server_v6_mode_requires_version_6() {
        let cfg = server_from(
            r#"
[snell-server]
listen = 0.0.0.0:8388
psk = testpsk-16-byte!
version = 6
mode = unshaped
"#,
        )
        .unwrap();
        assert_eq!(cfg.protocol, Some(ProtocolVersion::V6(V6Mode::Unshaped)));

        for (mode, expected) in [
            ("default", V6Mode::Default),
            ("unshaped", V6Mode::Unshaped),
            ("unsafe-raw", V6Mode::UnsafeRaw),
        ] {
            let cfg = server_from(&format!(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\nversion=6\nmode={mode}\n"
            ))
            .unwrap();
            assert_eq!(cfg.protocol, Some(ProtocolVersion::V6(expected)));
        }

        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\nmode=default\n"
            ),
            Err(ConfigError::Invalid { key: "mode", .. })
        ));
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\nversion=4\nmode=default\n"
            ),
            Err(ConfigError::Invalid { key: "mode", .. })
        ));
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\nversion=v6\nmode=default\n"
            ),
            Err(ConfigError::Invalid { key: "mode", .. })
        ));
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\nversion=6\nmode=v6-default\n"
            ),
            Err(ConfigError::Invalid { key: "mode", .. })
        ));
        assert!(matches!(
            server_from(
                "[snell-server]\nlisten=0.0.0.0:8388\npsk=testpsk-16-byte!\nversion=6\nmode=unsafe_raw\n"
            ),
            Err(ConfigError::Invalid { key: "mode", .. })
        ));
    }

    #[test]
    fn rejects_bad_values() {
        assert!(matches!(
            client_from(
                "[snell-client]\nlisten=example.com:1080\nserver=1.1.1.1:1\npsk=testpsk-16-byte!\nversion=v4\n"
            ),
            Err(ConfigError::Invalid { key: "listen", .. })
        ));
        assert!(matches!(
            client_from(
                "[snell-client]\nlisten=127.0.0.1:1\nserver=1.1.1.1:1\npsk=short\nversion=v4\n"
            ),
            Err(ConfigError::Invalid { key: "psk", .. })
        ));
        assert!(matches!(
            client_from(
                "[snell-client]\nlisten=127.0.0.1:1\nserver=1.1.1.1:1\npsk=testpsk-16-byte!\nversion=bogus\n"
            ),
            Err(ConfigError::Invalid { key: "version", .. })
        ));
    }
}

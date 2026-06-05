use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;

use ini::Ini;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::protocol::header::validate_version;
use crate::{DEFAULT_VERSION, VERSION_5};

const SNELL_SERVER_SECTION: &str = "snell-server";
const SNELL_CLIENT_SECTION: &str = "snell-client";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Zeroizing<Vec<u8>>,
    pub version: u8,
    pub ipv6: bool,
    pub tcp_fast_open: bool,
    pub quic_proxy: bool,
    pub upstream_socks5: Option<UpstreamSocks5>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamSocks5 {
    pub addr: SocketAddr,
}

impl ServerConfig {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let config = Ini::load_from_file(path).map_err(|err| Error::Config(err.to_string()))?;
        Self::from_ini(&config)
    }

    fn from_ini(config: &Ini) -> Result<Self> {
        let section = config
            .section(Some(SNELL_SERVER_SECTION))
            .ok_or_else(|| Error::Config(format!("missing [{SNELL_SERVER_SECTION}] section")))?;

        let listen = required(section, SNELL_SERVER_SECTION, "listen").and_then(parse_listen)?;
        let psk = required(section, SNELL_SERVER_SECTION, "psk")?;
        if psk.is_empty() {
            return Err(Error::Config("snell-server.psk is empty".to_owned()));
        }

        let version = optional_u8(section, SNELL_SERVER_SECTION, "version")?.unwrap_or(VERSION_5);
        validate_version(version)?;
        let quic_proxy = optional_bool(section, SNELL_SERVER_SECTION, "quic_proxy")?
            .unwrap_or(version == VERSION_5);
        if quic_proxy && version != VERSION_5 {
            return Err(Error::Config(
                "snell-server.quic_proxy requires version = 5".to_owned(),
            ));
        }

        Ok(Self {
            listen,
            psk: Zeroizing::new(psk.as_bytes().to_vec()),
            version,
            ipv6: optional_bool(section, SNELL_SERVER_SECTION, "ipv6")?.unwrap_or(false),
            tcp_fast_open: optional_bool(section, SNELL_SERVER_SECTION, "tcp_fast_open")?
                .unwrap_or(false),
            quic_proxy,
            upstream_socks5: optional_socket_addr(
                section,
                SNELL_SERVER_SECTION,
                "upstream_socks5",
            )?
            .map(|addr| UpstreamSocks5 { addr }),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Zeroizing<Vec<u8>>,
    pub version: u8,
    pub reuse: bool,
    pub quic_proxy: bool,
}

impl ClientConfig {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let config = Ini::load_from_file(path).map_err(|err| Error::Config(err.to_string()))?;
        Self::from_ini(&config)
    }

    fn from_ini(config: &Ini) -> Result<Self> {
        let section = config
            .section(Some(SNELL_CLIENT_SECTION))
            .ok_or_else(|| Error::Config(format!("missing [{SNELL_CLIENT_SECTION}] section")))?;

        let listen = required(section, SNELL_CLIENT_SECTION, "listen").and_then(parse_listen)?;
        let server = required(section, SNELL_CLIENT_SECTION, "server")?
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid snell-client.server: {err}")))?;
        let psk = required(section, SNELL_CLIENT_SECTION, "psk")?;
        if psk.is_empty() {
            return Err(Error::Config("snell-client.psk is empty".to_owned()));
        }

        let version =
            optional_u8(section, SNELL_CLIENT_SECTION, "version")?.unwrap_or(DEFAULT_VERSION);
        validate_version(version)?;
        let quic_proxy = optional_bool(section, SNELL_CLIENT_SECTION, "quic_proxy")?
            .unwrap_or(version == VERSION_5);
        if quic_proxy && version != VERSION_5 {
            return Err(Error::Config(
                "snell-client.quic_proxy requires version = 5".to_owned(),
            ));
        }

        Ok(Self {
            listen,
            server,
            psk: Zeroizing::new(psk.as_bytes().to_vec()),
            version,
            reuse: optional_bool(section, SNELL_CLIENT_SECTION, "reuse")?.unwrap_or(false),
            quic_proxy,
        })
    }
}

fn required<'a>(section: &'a ini::Properties, section_name: &str, key: &str) -> Result<&'a str> {
    section
        .get(key)
        .map(str::trim)
        .ok_or_else(|| Error::Config(format!("missing {section_name}.{key}")))
}

fn optional_bool(section: &ini::Properties, section_name: &str, key: &str) -> Result<Option<bool>> {
    let Some(value) = section.get(key).map(str::trim) else {
        return Ok(None);
    };
    match value {
        "true" | "yes" | "1" | "on" => Ok(Some(true)),
        "false" | "no" | "0" | "off" => Ok(Some(false)),
        _ => Err(Error::Config(format!(
            "invalid boolean for {section_name}.{key}: {value}"
        ))),
    }
}

fn optional_u8(section: &ini::Properties, section_name: &str, key: &str) -> Result<Option<u8>> {
    let Some(value) = section.get(key).map(str::trim) else {
        return Ok(None);
    };
    value
        .parse::<u8>()
        .map(Some)
        .map_err(|err| Error::Config(format!("invalid integer for {section_name}.{key}: {err}")))
}

fn optional_socket_addr(
    section: &ini::Properties,
    section_name: &str,
    key: &str,
) -> Result<Option<SocketAddr>> {
    let Some(value) = section.get(key).map(str::trim) else {
        return Ok(None);
    };
    value
        .parse::<SocketAddr>()
        .map(Some)
        .map_err(|err| Error::Config(format!("invalid {section_name}.{key}: {err}")))
}

fn parse_listen(value: &str) -> Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }

    if let Some(port) = value.strip_prefix(":::") {
        let port = port
            .parse::<u16>()
            .map_err(|err| Error::Config(format!("invalid listen address {value}: {err}")))?;
        return Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
    }

    Err(Error::Config(format!("invalid listen address: {value}")))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{ClientConfig, ServerConfig};
    use crate::error::Error;

    fn parse_server_config(input: &str) -> crate::error::Result<ServerConfig> {
        let config =
            ini::Ini::load_from_str(input).map_err(|err| Error::Config(err.to_string()))?;
        ServerConfig::from_ini(&config)
    }

    fn parse_client_config(input: &str) -> crate::error::Result<ClientConfig> {
        let config =
            ini::Ini::load_from_str(input).map_err(|err| Error::Config(err.to_string()))?;
        ClientConfig::from_ini(&config)
    }

    #[test]
    fn parses_snell_server_config() {
        let config = parse_server_config(
            r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
ipv6 = true
tcp_fast_open = true
"#,
        )
        .unwrap();

        assert_eq!(
            config.listen,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 29246)
        );
        assert_eq!(&config.psk[..], b"PSKMOCK");
        assert!(config.ipv6);
        assert!(config.tcp_fast_open);
        assert_eq!(config.version, crate::VERSION_5);
        assert!(config.quic_proxy);
        assert_eq!(config.upstream_socks5, None);
    }

    #[test]
    fn parses_snell_ipv6_listen_shorthand() {
        let config = parse_server_config(
            r#"
[snell-server]
listen = :::11807
psk = PSKMOCK
"#,
        )
        .unwrap();

        assert_eq!(
            config.listen,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 11807)
        );
        assert!(!config.ipv6);
        assert!(!config.tcp_fast_open);
        assert_eq!(config.upstream_socks5, None);
    }

    #[test]
    fn parses_snell_server_upstream_socks5() {
        let config = parse_server_config(
            r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
upstream_socks5 = 127.0.0.1:1080
"#,
        )
        .unwrap();

        assert_eq!(
            config.upstream_socks5,
            Some(super::UpstreamSocks5 {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)
            })
        );
    }

    #[test]
    fn v5_defaults_quic_proxy_on() {
        let config = parse_server_config(
            r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
version = 5
"#,
        )
        .unwrap();

        assert_eq!(config.version, crate::VERSION_5);
        assert!(config.quic_proxy);
    }

    #[test]
    fn rejects_quic_proxy_before_v5() {
        assert!(matches!(
            parse_server_config(
                r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
version = 4
quic_proxy = true
"#
            ),
            Err(Error::Config(message)) if message.contains("quic_proxy requires version = 5")
        ));
    }

    #[test]
    fn rejects_missing_server_section() {
        assert!(matches!(
            parse_server_config("listen = 0.0.0.0:29246"),
            Err(Error::Config(message)) if message.contains("missing [snell-server]")
        ));
    }

    #[test]
    fn parses_snell_client_config() {
        let config = parse_client_config(
            r#"
[snell-client]
listen = 127.0.0.1:1080
server = 127.0.0.1:29246
psk = PSKMOCK
reuse = true
"#,
        )
        .unwrap();

        assert_eq!(
            config.listen,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)
        );
        assert_eq!(
            config.server,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 29246)
        );
        assert_eq!(&config.psk[..], b"PSKMOCK");
        assert!(config.reuse);
        assert_eq!(config.version, crate::DEFAULT_VERSION);
        assert!(!config.quic_proxy);
    }

    #[test]
    fn parses_snell_client_config_defaults() {
        let config = parse_client_config(
            r#"
[snell-client]
listen = 127.0.0.1:1080
server = 127.0.0.1:29246
psk = PSKMOCK
"#,
        )
        .unwrap();

        assert!(!config.reuse);
    }

    #[test]
    fn parses_v5_client_quic_proxy_default() {
        let config = parse_client_config(
            r#"
[snell-client]
listen = 127.0.0.1:1080
server = 127.0.0.1:29246
psk = PSKMOCK
version = 5
"#,
        )
        .unwrap();

        assert_eq!(config.version, crate::VERSION_5);
        assert!(config.quic_proxy);
    }
}

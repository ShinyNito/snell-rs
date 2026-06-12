use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;

use ini::Ini;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::net::dns::DnsIpPreference;
use crate::protocol::version::{DEFAULT_CLIENT_VERSION, ProtocolVersion};

const SNELL_SERVER_SECTION: &str = "snell-server";
const SNELL_CLIENT_SECTION: &str = "snell-client";
pub(crate) const TCP_BRUTAL_CWND_GAIN: u32 = 20;
const TCP_BRUTAL_SEND_MBIT_TO_BYTES: u64 = 125_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub listen: Vec<SocketAddr>,
    pub psk: Zeroizing<Vec<u8>>,
    pub ipv6: bool,
    pub dns: Option<SocketAddr>,
    pub dns_ip_preference: DnsIpPreference,
    pub tcp_fast_open: bool,
    pub quic_proxy: bool,
    pub tcp_brutal: Option<TcpBrutalConfig>,
    pub upstream_socks5: Option<UpstreamSocks5>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamSocks5 {
    pub addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBrutalConfig {
    pub rate_bytes_per_sec: u64,
    pub cwnd_gain: u32,
}

impl ServerConfig {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let config = Ini::load_from_file(path).map_err(|err| Error::Config(err.to_string()))?;
        Self::from_ini(&config)
    }

    fn from_ini(config: &Ini) -> Result<Self> {
        let section = config
            .section(Some(SNELL_SERVER_SECTION))
            .ok_or_else(|| missing_section(SNELL_SERVER_SECTION))?;

        let listen =
            required(section, SNELL_SERVER_SECTION, "listen").and_then(parse_listen_addrs)?;
        let psk = required(section, SNELL_SERVER_SECTION, "psk")?;
        if psk.is_empty() {
            return Err(Error::Config("snell-server.psk is empty".to_owned()));
        }

        if section.get("version").is_some() {
            return Err(Error::Config(
                "snell-server.version is no longer supported; TCP server auto-detects Snell protocol versions".to_owned(),
            ));
        }
        let quic_proxy =
            optional_bool(section, SNELL_SERVER_SECTION, "quic_proxy")?.unwrap_or(false);
        if quic_proxy && listen.len() > 1 {
            return Err(Error::Config(
                "snell-server.listen multiple addresses are not supported with quic_proxy"
                    .to_owned(),
            ));
        }

        Ok(Self {
            listen,
            psk: Zeroizing::new(psk.as_bytes().to_vec()),
            ipv6: optional_bool(section, SNELL_SERVER_SECTION, "ipv6")?.unwrap_or(false),
            dns: optional_dns_addr(section, SNELL_SERVER_SECTION, "dns")?,
            dns_ip_preference: optional_dns_ip_preference(
                section,
                SNELL_SERVER_SECTION,
                "dns-ip-preference",
            )?
            .unwrap_or_default(),
            tcp_fast_open: optional_bool(section, SNELL_SERVER_SECTION, "tcp_fast_open")?
                .unwrap_or(false),
            quic_proxy,
            tcp_brutal: optional_tcp_brutal(section, SNELL_SERVER_SECTION)?,
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
    pub version: ProtocolVersion,
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
            .ok_or_else(|| missing_section(SNELL_CLIENT_SECTION))?;

        let listen =
            required(section, SNELL_CLIENT_SECTION, "listen").and_then(parse_listen_addr)?;
        let server = required(section, SNELL_CLIENT_SECTION, "server")?
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid snell-client.server: {err}")))?;
        let psk = required(section, SNELL_CLIENT_SECTION, "psk")?;
        if psk.is_empty() {
            return Err(Error::Config("snell-client.psk is empty".to_owned()));
        }

        let version = optional_version(section, SNELL_CLIENT_SECTION, "version")?
            .unwrap_or(DEFAULT_CLIENT_VERSION);
        let quic_proxy = optional_bool(section, SNELL_CLIENT_SECTION, "quic_proxy")?
            .unwrap_or(version.uses_quic_proxy());
        if quic_proxy && !version.uses_quic_proxy() {
            return Err(Error::Config(
                "snell-client.quic_proxy requires version = 5".to_owned(),
            ));
        }
        reject_client_tcp_brutal(section)?;

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
        .ok_or_else(|| missing_key(section_name, key))
}

fn missing_section(section_name: &str) -> Error {
    Error::Config(format!("missing [{section_name}] section"))
}

fn missing_key(section_name: &str, key: &str) -> Error {
    Error::Config(format!("missing {section_name}.{key}"))
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

fn optional_version(
    section: &ini::Properties,
    section_name: &str,
    key: &str,
) -> Result<Option<ProtocolVersion>> {
    optional_u8(section, section_name, key)?
        .map(ProtocolVersion::try_from)
        .transpose()
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

fn optional_u64(section: &ini::Properties, section_name: &str, key: &str) -> Result<Option<u64>> {
    let Some(value) = section.get(key).map(str::trim) else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|err| Error::Config(format!("invalid integer for {section_name}.{key}: {err}")))
}

fn optional_tcp_brutal(
    section: &ini::Properties,
    section_name: &str,
) -> Result<Option<TcpBrutalConfig>> {
    if !optional_bool(section, section_name, "tcp_brutal")?.unwrap_or(false) {
        return Ok(None);
    }

    let send_mbps = optional_u64(section, section_name, "tcp_brutal_send_mbps")?
        .ok_or_else(|| missing_key(section_name, "tcp_brutal_send_mbps"))?;
    if send_mbps == 0 {
        return Err(Error::Config(format!(
            "{section_name}.tcp_brutal_send_mbps must be greater than 0"
        )));
    }
    let rate_bytes_per_sec = send_mbps
        .checked_mul(TCP_BRUTAL_SEND_MBIT_TO_BYTES)
        .ok_or_else(|| {
            Error::Config(format!("{section_name}.tcp_brutal_send_mbps is too large"))
        })?;

    Ok(Some(TcpBrutalConfig {
        rate_bytes_per_sec,
        cwnd_gain: TCP_BRUTAL_CWND_GAIN,
    }))
}

fn reject_client_tcp_brutal(section: &ini::Properties) -> Result<()> {
    if section.contains_key("tcp_brutal") || section.contains_key("tcp_brutal_send_mbps") {
        return Err(Error::Config(
            "snell-client.tcp_brutal is only supported in [snell-server]".to_owned(),
        ));
    }
    Ok(())
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

fn optional_dns_addr(
    section: &ini::Properties,
    section_name: &str,
    key: &str,
) -> Result<Option<SocketAddr>> {
    let Some(value) = section.get(key).map(str::trim) else {
        return Ok(None);
    };
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(Some(addr));
    }
    value
        .parse::<IpAddr>()
        .map(|ip| Some(SocketAddr::new(ip, 53)))
        .map_err(|err| Error::Config(format!("invalid {section_name}.{key}: {err}")))
}

fn optional_dns_ip_preference(
    section: &ini::Properties,
    section_name: &str,
    key: &str,
) -> Result<Option<DnsIpPreference>> {
    let Some(value) = section.get(key).map(str::trim) else {
        return Ok(None);
    };
    DnsIpPreference::parse(value)
        .map(Some)
        .ok_or_else(|| Error::Config(format!("invalid {section_name}.{key}: {value}")))
}

fn parse_listen_addrs(value: &str) -> Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(Error::Config(format!("invalid listen address: {value}")));
        }
        addrs.push(parse_listen_addr(raw)?);
    }
    if addrs.is_empty() {
        return Err(Error::Config("snell-server.listen is empty".to_owned()));
    }
    Ok(addrs)
}

fn parse_listen_addr(value: &str) -> Result<SocketAddr> {
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
mod tests;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{ClientConfig, ServerConfig, TcpBrutalConfig};
use crate::error::Error;
use crate::net::dns::DnsIpPreference;
use crate::protocol::version::DEFAULT_CLIENT_VERSION;

fn parse_server_config(input: &str) -> crate::error::Result<ServerConfig> {
    let config = ini::Ini::load_from_str(input).map_err(|err| Error::Config(err.to_string()))?;
    ServerConfig::from_ini(&config)
}

fn parse_client_config(input: &str) -> crate::error::Result<ClientConfig> {
    let config = ini::Ini::load_from_str(input).map_err(|err| Error::Config(err.to_string()))?;
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
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 29246)]
    );
    assert_eq!(&config.psk[..], b"PSKMOCK");
    assert!(config.ipv6);
    assert_eq!(config.dns, None);
    assert_eq!(config.dns_ip_preference, DnsIpPreference::Default);
    assert!(config.tcp_fast_open);
    assert!(!config.quic_proxy);
    assert_eq!(config.tcp_brutal, None);
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
        vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 11807)]
    );
    assert!(!config.ipv6);
    assert_eq!(config.dns, None);
    assert!(!config.tcp_fast_open);
    assert_eq!(config.tcp_brutal, None);
    assert_eq!(config.upstream_socks5, None);
}

#[test]
fn parses_snell_server_multiple_listen_addrs() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:7177, [::]:7177
psk = PSKMOCK
"#,
    )
    .unwrap();

    assert_eq!(
        config.listen,
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7177),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 7177),
        ]
    );
    assert!(!config.quic_proxy);
}

#[test]
fn rejects_multiple_listen_addrs_with_quic_proxy() {
    assert!(matches!(
        parse_server_config(
            r#"
[snell-server]
listen = 0.0.0.0:7177, [::]:7177
psk = PSKMOCK
quic_proxy = true
"#
        ),
        Err(Error::Config(message)) if message.contains("multiple addresses")
    ));
}

#[test]
fn parses_snell_server_tcp_brutal_config() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
tcp_brutal = true
tcp_brutal_send_mbps = 100
"#,
    )
    .unwrap();

    assert_eq!(
        config.tcp_brutal,
        Some(TcpBrutalConfig {
            rate_bytes_per_sec: 12_500_000,
            cwnd_gain: super::TCP_BRUTAL_CWND_GAIN,
        })
    );
}

#[test]
fn rejects_server_tcp_brutal_without_send_rate() {
    assert!(matches!(
        parse_server_config(
            r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
tcp_brutal = true
"#
        ),
        Err(Error::Config(message)) if message.contains("missing snell-server.tcp_brutal_send_mbps")
    ));
}

#[test]
fn rejects_snell_client_tcp_brutal_config() {
    assert!(matches!(
        parse_client_config(
            r#"
[snell-client]
listen = 127.0.0.1:1080
server = 127.0.0.1:29246
psk = PSKMOCK
tcp_brutal = true
tcp_brutal_send_mbps = 8
"#
        ),
        Err(Error::Config(message)) if message.contains("only supported in [snell-server]")
    ));
}

#[test]
fn rejects_zero_tcp_brutal_send_rate() {
    assert!(matches!(
        parse_server_config(
            r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
tcp_brutal = true
tcp_brutal_send_mbps = 0
"#
        ),
        Err(Error::Config(message)) if message.contains("must be greater than 0")
    ));
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
fn parses_snell_server_dns_addr() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
dns = 1.1.1.1
"#,
    )
    .unwrap();

    assert_eq!(
        config.dns,
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53))
    );
}

#[test]
fn parses_snell_server_dns_addr_with_port() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
dns = 1.1.1.1:5353
"#,
    )
    .unwrap();

    assert_eq!(
        config.dns,
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 5353))
    );
}

#[test]
fn parses_snell_server_dns_ip_preference() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
dns-ip-preference = prefer-ipv6
"#,
    )
    .unwrap();

    assert_eq!(config.dns_ip_preference, DnsIpPreference::PreferIpv6);
}

#[test]
fn rejects_invalid_snell_server_dns_ip_preference() {
    assert!(matches!(
        parse_server_config(
            r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
dns-ip-preference = prefer-both
"#
        ),
        Err(Error::Config(message)) if message.contains("invalid snell-server.dns-ip-preference")
    ));
}

#[test]
fn rejects_server_version_config() {
    assert!(matches!(
        parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
version = 5
"#
        ),
        Err(Error::Config(message)) if message.contains("version is no longer supported")
    ));
}

#[test]
fn accepts_explicit_server_quic_proxy() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
quic_proxy = true
"#,
    )
    .unwrap();

    assert!(config.quic_proxy);
}

#[test]
fn server_defaults_quic_proxy_off() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
"#,
    )
    .unwrap();

    assert!(!config.quic_proxy);
}

#[test]
fn accepts_server_quic_proxy_as_independent_feature() {
    let config = parse_server_config(
        r#"
[snell-server]
listen = 0.0.0.0:29246
psk = PSKMOCK
quic_proxy = true
"#,
    )
    .unwrap();

    assert!(config.quic_proxy);
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
    assert_eq!(config.version, DEFAULT_CLIENT_VERSION);
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

    assert_eq!(config.version, crate::ProtocolVersion::V5);
    assert!(config.quic_proxy);
}

#[test]
fn parses_v6_client_without_quic_proxy() {
    let config = parse_client_config(
        r#"
[snell-client]
listen = 127.0.0.1:1080
server = 127.0.0.1:29246
psk = PSKMOCK
version = 6
"#,
    )
    .unwrap();

    assert_eq!(config.version, crate::ProtocolVersion::V6);
    assert!(!config.quic_proxy);
}

#[test]
fn rejects_v6_client_quic_proxy() {
    assert!(matches!(
        parse_client_config(
            r#"
[snell-client]
listen = 127.0.0.1:1080
server = 127.0.0.1:29246
psk = PSKMOCK
version = 6
quic_proxy = true
"#
        ),
        Err(Error::Config(message)) if message.contains("quic_proxy requires version = 5")
    ));
}

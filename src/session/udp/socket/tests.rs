use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::select_udp_target;
use crate::error::Error;
use crate::net::dns::DnsIpPreference;

#[test]
fn domain_target_prefers_ipv4_when_ipv6_is_disabled() {
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

    assert_eq!(
        select_udp_target(&[v6, v4], false, DnsIpPreference::Default).unwrap(),
        v4
    );
    assert_eq!(
        select_udp_target(&[v6, v4], true, DnsIpPreference::Default).unwrap(),
        v6
    );
    assert_eq!(
        select_udp_target(&[v6, v4], true, DnsIpPreference::PreferIpv4).unwrap(),
        v4
    );
    assert_eq!(
        select_udp_target(&[v4, v6], true, DnsIpPreference::PreferIpv6).unwrap(),
        v6
    );
}

#[test]
fn domain_target_rejects_ipv6_only_when_ipv6_is_disabled() {
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);

    assert!(matches!(
        select_udp_target(&[v6], false, DnsIpPreference::Default),
        Err(Error::Ipv6Disabled)
    ));
}

#[test]
fn domain_target_honors_only_preferences() {
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

    assert_eq!(
        select_udp_target(&[v6, v4], true, DnsIpPreference::Ipv4Only).unwrap(),
        v4
    );
    assert_eq!(
        select_udp_target(&[v4, v6], true, DnsIpPreference::Ipv6Only).unwrap(),
        v6
    );
    assert!(matches!(
        select_udp_target(&[v6], false, DnsIpPreference::Ipv4Only),
        Err(Error::InvalidAddressType)
    ));
}

use std::net::{IpAddr, SocketAddr};

use crate::config::UpstreamSocks5;
use crate::net::dns::{DnsIpPreference, DnsResolver};
use crate::protocol::udp::AddressRef;

pub(crate) mod direct;
pub(crate) mod quic;
pub(crate) mod snell;
pub(crate) mod socks5;
pub(crate) mod tcp;
pub(crate) mod udp;

pub(crate) use quic::{open_quic_udp, run_quic_proxy_response_session};
pub(crate) use tcp::open_tcp;
pub(crate) use udp::{PreparedUdpProxy, PreparedUdpRelay, open_udp, validate_proxy_udp_target};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    pub uploaded: u64,
    pub downloaded: u64,
}

#[derive(Clone, Debug)]
pub struct RelayOptions {
    pub ipv6: bool,
    pub dns_ip_preference: DnsIpPreference,
    pub upstream: UpstreamRelay,
    pub resolver: DnsResolver,
}

impl RelayOptions {
    #[cfg(test)]
    pub(crate) fn direct(ipv6: bool, resolver: DnsResolver) -> Self {
        Self {
            ipv6,
            dns_ip_preference: DnsIpPreference::Default,
            upstream: UpstreamRelay::Direct,
            resolver,
        }
    }

    #[cfg(test)]
    pub(crate) fn socks5(ipv6: bool, proxy_addr: SocketAddr, resolver: DnsResolver) -> Self {
        Self {
            ipv6,
            dns_ip_preference: DnsIpPreference::Default,
            upstream: UpstreamRelay::Socks5(proxy_addr),
            resolver,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UpstreamRelay {
    #[default]
    Direct,
    Socks5(SocketAddr),
}

impl From<Option<UpstreamSocks5>> for UpstreamRelay {
    fn from(upstream: Option<UpstreamSocks5>) -> Self {
        match upstream {
            Some(upstream) => Self::Socks5(upstream.addr),
            None => Self::Direct,
        }
    }
}

fn address_ref_from_host(host: &str) -> AddressRef<'_> {
    match host.parse::<IpAddr>() {
        Ok(ip) => AddressRef::Ip(ip),
        Err(_) => AddressRef::Domain(host),
    }
}

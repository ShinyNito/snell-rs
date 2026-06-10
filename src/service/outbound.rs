use std::net::{IpAddr, SocketAddr};

use crate::protocol::udp::AddressRef;
use crate::service::runtime::config::UpstreamSocks5;

pub(crate) mod direct;
pub(crate) mod quic;
pub(crate) mod snell;
pub(crate) mod socks5;
pub(crate) mod tcp;
pub(crate) mod udp;

pub(crate) use quic::{QuicProxyRelay, open_quic_udp, run_quic_proxy_response_session};
pub(crate) use tcp::open_tcp;
pub(crate) use udp::{
    PreparedUdpProxy, PreparedUdpRelay, open_udp, send_udp_payload, validate_proxy_udp_target,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    pub uploaded: u64,
    pub downloaded: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayOptions {
    pub ipv6: bool,
    pub upstream: UpstreamRelay,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            ipv6: true,
            upstream: UpstreamRelay::Direct,
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

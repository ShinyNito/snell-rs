use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::net::dns::DnsResolver;
use crate::protocol::udp::{AddressRef, UdpPacketRef};

use super::socks5::{Socks5UdpRelayEndpoint, open_udp_associate_via_socks5};
use super::{RelayOptions, UpstreamRelay};

pub(crate) enum PreparedUdpRelay {
    Direct,
    Proxy(PreparedUdpProxy),
}

pub(crate) struct PreparedUdpProxy {
    pub(crate) control: TcpStream,
    pub(crate) relay_addr: SocketAddr,
}

pub(crate) async fn open_udp(options: RelayOptions) -> Result<PreparedUdpRelay> {
    match options.upstream {
        UpstreamRelay::Direct => Ok(PreparedUdpRelay::Direct),
        UpstreamRelay::Socks5(proxy_addr) => {
            let association = open_udp_associate_via_socks5(proxy_addr).await?;
            let relay_addr = resolve_socks5_udp_relay_addr(
                proxy_addr,
                association.relay_endpoint,
                &options.resolver,
            )
            .await?;
            Ok(PreparedUdpRelay::Proxy(PreparedUdpProxy {
                control: association.control,
                relay_addr,
            }))
        }
    }
}

pub(crate) async fn resolve_socks5_udp_relay_addr(
    proxy_addr: SocketAddr,
    endpoint: Socks5UdpRelayEndpoint,
    resolver: &DnsResolver,
) -> Result<SocketAddr> {
    match endpoint {
        Socks5UdpRelayEndpoint::Ip(addr) => Ok(addr),
        Socks5UdpRelayEndpoint::Domain { host, port } => {
            let addrs = resolver.lookup_socket_addrs(host.as_str(), port).await?;
            select_socks5_udp_relay_addr(proxy_addr, &addrs)
        }
    }
}

fn select_socks5_udp_relay_addr(
    proxy_addr: SocketAddr,
    addrs: &[SocketAddr],
) -> Result<SocketAddr> {
    let want_ipv4 = proxy_addr.is_ipv4();
    let first = addrs.first().copied().ok_or(Error::InvalidAddressType)?;
    if first.is_ipv4() == want_ipv4 {
        return Ok(first);
    }
    Ok(addrs
        .iter()
        .copied()
        .skip(1)
        .find(|addr| addr.is_ipv4() == want_ipv4)
        .unwrap_or(first))
}

pub(crate) const fn validate_proxy_udp_target(packet: UdpPacketRef<'_>, ipv6: bool) -> Result<()> {
    if let AddressRef::Ip(ip) = packet.address
        && !ipv6
        && ip.is_ipv6()
    {
        return Err(Error::Ipv6Disabled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::select_socks5_udp_relay_addr;
    use crate::error::Error;

    #[test]
    fn socks5_udp_relay_addr_prefers_proxy_address_family_for_domains() {
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353);
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 5353);

        assert_eq!(
            select_socks5_udp_relay_addr(proxy_addr, &[v6, v4]).unwrap(),
            v4
        );
    }

    #[test]
    fn socks5_udp_relay_addr_falls_back_to_first_resolved_addr() {
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353);

        assert_eq!(select_socks5_udp_relay_addr(proxy_addr, &[v6]).unwrap(), v6);
    }

    #[test]
    fn socks5_udp_relay_addr_rejects_empty_resolution() {
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
        let addrs: [SocketAddr; 0] = [];

        std::assert_matches!(
            select_socks5_udp_relay_addr(proxy_addr, &addrs),
            Err(Error::InvalidAddressType)
        );
    }
}

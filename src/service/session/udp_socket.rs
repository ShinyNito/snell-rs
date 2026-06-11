use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::protocol::udp::{AddressRef, UdpPacketRef};
use crate::service::dns::DnsResolver;

pub(super) const UDP_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct UdpSockets {
    pub(super) v4: Arc<UdpSocket>,
    pub(super) v6: Option<Arc<UdpSocket>>,
}

impl UdpSockets {
    pub(super) async fn bind(ipv6: bool) -> Result<Self> {
        let v4 =
            Arc::new(bind_udp_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?);
        let v6 = if ipv6 {
            Some(Arc::new(
                bind_udp_socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await?,
            ))
        } else {
            None
        };

        Ok(Self { v4, v6 })
    }

    pub(super) fn socket_for(&self, target: SocketAddr) -> Result<Arc<UdpSocket>> {
        match target.ip() {
            IpAddr::V4(_) => Ok(self.v4.clone()),
            IpAddr::V6(_) => self.v6.clone().ok_or(Error::Ipv6Disabled),
        }
    }
}

pub(super) async fn resolve_udp_target(
    packet: UdpPacketRef<'_>,
    ipv6: bool,
    resolver: &DnsResolver,
) -> Result<SocketAddr> {
    match packet.address {
        AddressRef::Ip(ip) => {
            if !ipv6 && ip.is_ipv6() {
                return Err(Error::Ipv6Disabled);
            }
            Ok(SocketAddr::new(ip, packet.port))
        }
        AddressRef::Domain(host) => {
            let addrs = timeout(
                UDP_RESOLVE_TIMEOUT,
                resolver.lookup_socket_addrs(host, packet.port),
            )
            .await
            .map_err(|_| Error::Timeout("udp target resolution"))??;
            select_udp_target(addrs, ipv6)
        }
    }
}

pub(super) fn relay_bind_ip(relay_addr: SocketAddr) -> IpAddr {
    if relay_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}

pub(super) fn select_udp_target(
    addrs: impl IntoIterator<Item = SocketAddr>,
    ipv6: bool,
) -> Result<SocketAddr> {
    let mut saw_disallowed_ipv6 = false;
    for addr in addrs {
        if ipv6 || addr.is_ipv4() {
            return Ok(addr);
        }
        saw_disallowed_ipv6 = true;
    }

    if saw_disallowed_ipv6 {
        Err(Error::Ipv6Disabled)
    } else {
        Err(Error::InvalidAddressType)
    }
}

pub(super) async fn bind_udp_socket(bind_addr: SocketAddr) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(bind_addr).await?)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::select_udp_target;
    use crate::error::Error;

    #[test]
    fn domain_target_prefers_ipv4_when_ipv6_is_disabled() {
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

        assert_eq!(select_udp_target([v6, v4], false).unwrap(), v4);
        assert_eq!(select_udp_target([v6, v4], true).unwrap(), v6);
    }

    #[test]
    fn domain_target_rejects_ipv6_only_when_ipv6_is_disabled() {
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);

        assert!(matches!(
            select_udp_target([v6], false),
            Err(Error::Ipv6Disabled)
        ));
    }
}

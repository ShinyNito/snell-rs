use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::net::dns::DnsIpPreference;

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

pub(super) const fn relay_bind_ip(relay_addr: SocketAddr) -> IpAddr {
    if relay_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}

pub(super) fn select_udp_target(
    addrs: &[SocketAddr],
    ipv6: bool,
    dns_ip_preference: DnsIpPreference,
) -> Result<SocketAddr> {
    let selected = dns_ip_preference.select_addrs(addrs, ipv6);
    if let Some(addr) = selected.into_iter().next() {
        return Ok(addr);
    }

    if !ipv6
        && dns_ip_preference != DnsIpPreference::Ipv4Only
        && addrs.iter().any(SocketAddr::is_ipv6)
    {
        Err(Error::Ipv6Disabled)
    } else {
        Err(Error::InvalidAddressType)
    }
}

pub(super) async fn bind_udp_socket(bind_addr: SocketAddr) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(bind_addr).await?)
}

#[cfg(test)]
mod tests;

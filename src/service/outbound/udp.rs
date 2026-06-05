use tokio::net::{TcpStream, UdpSocket};

use crate::error::{Error, Result};
use crate::protocol::udp::{AddressRef, UdpPacketRef};

use super::socks5::open_udp_associate_via_socks5;
use super::{RelayOptions, UpstreamRelay};

pub(crate) enum PreparedUdpRelay {
    Direct,
    Proxy(PreparedUdpProxy),
}

pub(crate) struct PreparedUdpProxy {
    pub(crate) control: TcpStream,
    pub(crate) relay_addr: std::net::SocketAddr,
}

pub(crate) async fn open_udp(options: RelayOptions) -> Result<PreparedUdpRelay> {
    match options.upstream {
        UpstreamRelay::Direct => Ok(PreparedUdpRelay::Direct),
        UpstreamRelay::Socks5(proxy_addr) => {
            let association = open_udp_associate_via_socks5(proxy_addr).await?;
            Ok(PreparedUdpRelay::Proxy(PreparedUdpProxy {
                control: association.control,
                relay_addr: association.relay_addr,
            }))
        }
    }
}

pub(crate) fn validate_proxy_udp_target(packet: UdpPacketRef<'_>, ipv6: bool) -> Result<()> {
    if let AddressRef::Ip(ip) = packet.address
        && !ipv6
        && ip.is_ipv6()
    {
        return Err(Error::Ipv6Disabled);
    }
    Ok(())
}

pub(crate) async fn send_udp_payload(
    socket: &UdpSocket,
    payload: &[u8],
    target: std::net::SocketAddr,
) -> Result<()> {
    let sent = socket.send_to(payload, target).await?;
    ensure_full_datagram_sent(sent, payload.len())
}

pub(crate) fn ensure_full_datagram_sent(sent: usize, expected: usize) -> Result<()> {
    if sent == expected {
        return Ok(());
    }

    Err(Error::ShortUdpWrite { sent, expected })
}

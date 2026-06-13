use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::protocol::socks5::{
    parse_udp_packet as parse_socks_udp_packet, write_udp_packet as write_socks_udp_packet,
};
use crate::session::udp::io::{UdpRecvBatch, UdpSendPacket, send_udp_batch};

use super::socks5::open_udp_associate_via_socks5;
use super::udp::resolve_socks5_udp_relay_addr;
use super::{RelayOptions, UpstreamRelay, address_ref_from_host};

pub(crate) struct QuicProxyRelay {
    outbound: Arc<UdpSocket>,
    target: QuicProxyRelayTarget,
    request: BytesMut,
    _control: Option<tokio::net::TcpStream>,
}

#[derive(Clone)]
enum QuicProxyRelayTarget {
    Direct(SocketAddr),
    Proxy {
        relay_addr: SocketAddr,
        host: String,
        port: u16,
    },
}

pub(crate) async fn open_quic_udp(
    host: String,
    port: u16,
    options: RelayOptions,
) -> Result<QuicProxyRelay> {
    match options.upstream {
        UpstreamRelay::Direct => {
            let target = resolve_udp_target(
                &host,
                port,
                options.ipv6,
                options.dns_ip_preference,
                &options.resolver,
            )
            .await?;
            let outbound = UdpSocket::bind(SocketAddr::new(relay_bind_ip(target), 0)).await?;
            Ok(QuicProxyRelay {
                outbound: Arc::new(outbound),
                target: QuicProxyRelayTarget::Direct(target),
                request: BytesMut::with_capacity(MAX_PACKET_SIZE + 512),
                _control: None,
            })
        }
        UpstreamRelay::Socks5(proxy_addr) => {
            if let Ok(ip) = host.parse::<IpAddr>()
                && !options.ipv6
                && ip.is_ipv6()
            {
                return Err(Error::Ipv6Disabled);
            }
            let association = open_udp_associate_via_socks5(proxy_addr).await?;
            let relay_addr = resolve_socks5_udp_relay_addr(
                proxy_addr,
                association.relay_endpoint,
                &options.resolver,
            )
            .await?;
            let outbound = UdpSocket::bind(SocketAddr::new(relay_bind_ip(relay_addr), 0)).await?;
            Ok(QuicProxyRelay {
                outbound: Arc::new(outbound),
                target: QuicProxyRelayTarget::Proxy {
                    relay_addr,
                    host,
                    port,
                },
                request: BytesMut::with_capacity(MAX_PACKET_SIZE + 512),
                _control: Some(association.control),
            })
        }
    }
}

impl QuicProxyRelay {
    pub(crate) async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        match &self.target {
            QuicProxyRelayTarget::Direct(target) => {
                send_udp_batch(
                    &self.outbound,
                    &[UdpSendPacket::single(payload, *target)],
                    MAX_PACKET_SIZE + 512,
                )
                .await?;
                Ok(())
            }
            QuicProxyRelayTarget::Proxy {
                relay_addr,
                host,
                port,
            } => {
                self.request.clear();
                write_socks_udp_packet(
                    &mut self.request,
                    address_ref_from_host(host),
                    *port,
                    payload,
                )?;
                send_udp_batch(
                    &self.outbound,
                    &[UdpSendPacket::single(&self.request, *relay_addr)],
                    MAX_PACKET_SIZE + 512,
                )
                .await?;
                Ok(())
            }
        }
    }

    pub(crate) fn response_relay(&self) -> QuicProxyResponseRelay {
        QuicProxyResponseRelay {
            outbound: self.outbound.clone(),
            target: self.target.clone(),
        }
    }
}

pub(crate) struct QuicProxyResponseRelay {
    outbound: Arc<UdpSocket>,
    target: QuicProxyRelayTarget,
}

pub(crate) async fn run_quic_proxy_response_session(
    server_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    relay: QuicProxyResponseRelay,
) -> Result<()> {
    let mut responses = UdpRecvBatch::new(MAX_PACKET_SIZE + 512);

    loop {
        let count = responses.recv_from(&relay.outbound).await?;
        for index in 0..count {
            let Some(response) = responses.get(index) else {
                continue;
            };
            let peer = response.peer();
            if response.is_oversized() {
                tracing::debug!("ignored oversized quic proxy response");
                continue;
            }
            match &relay.target {
                QuicProxyRelayTarget::Direct(target) => {
                    if peer != *target {
                        tracing::debug!(%peer, target = %target, "ignored quic proxy response from unexpected peer");
                        continue;
                    }
                    send_udp_batch(
                        &server_socket,
                        &[UdpSendPacket::single(response.payload(), client_addr)],
                        MAX_PACKET_SIZE + 512,
                    )
                    .await?;
                }
                QuicProxyRelayTarget::Proxy { relay_addr, .. } => {
                    if peer != *relay_addr {
                        tracing::debug!(%peer, relay_addr = %relay_addr, "ignored quic proxy response from unexpected proxy peer");
                        continue;
                    }
                    let packet = match parse_socks_udp_packet(response.payload()) {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::debug!(%err, "ignored invalid quic proxy response");
                            continue;
                        }
                    };
                    send_udp_batch(
                        &server_socket,
                        &[UdpSendPacket::single(packet.payload, client_addr)],
                        MAX_PACKET_SIZE + 512,
                    )
                    .await?;
                }
            }
        }
    }
}

async fn resolve_udp_target(
    host: &str,
    port: u16,
    ipv6: bool,
    dns_ip_preference: crate::net::dns::DnsIpPreference,
    resolver: &crate::net::dns::DnsResolver,
) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !ipv6 && ip.is_ipv6() {
            return Err(Error::Ipv6Disabled);
        }
        return Ok(SocketAddr::new(ip, port));
    }

    let addrs = timeout(
        Duration::from_secs(5),
        resolver.lookup_socket_addrs(host, port),
    )
    .await
    .map_err(|_| Error::DnsTimeout)??;
    select_udp_target(&addrs, ipv6, dns_ip_preference)
}

fn relay_bind_ip(relay_addr: SocketAddr) -> IpAddr {
    if relay_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}

fn select_udp_target(
    addrs: &[SocketAddr],
    ipv6: bool,
    dns_ip_preference: crate::net::dns::DnsIpPreference,
) -> Result<SocketAddr> {
    let selected = dns_ip_preference.select_addrs(addrs, ipv6);
    if let Some(addr) = selected.into_iter().next() {
        return Ok(addr);
    }

    if !ipv6
        && dns_ip_preference != crate::net::dns::DnsIpPreference::Ipv4Only
        && addrs.iter().any(SocketAddr::is_ipv6)
    {
        Err(Error::Ipv6Disabled)
    } else {
        Err(Error::InvalidAddressType)
    }
}

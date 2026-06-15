use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::protocol::socks5::{
    parse_udp_packet as parse_socks_udp_packet, write_udp_packet as write_socks_udp_packet,
};
use crate::relay::udp::io::{UdpRecvBatch, UdpSendBatch};

use super::socks5::open_udp_associate_via_socks5;
use super::udp::resolve_socks5_udp_relay_addr;
use super::{RelayOptions, UpstreamRelay, address_ref_from_host};

pub(crate) struct QuicProxyRelay {
    outbound: Arc<UdpSocket>,
    target: QuicProxyRelayTarget,
    buffers: Box<QuicProxyRelayBuffers>,
    _control: Option<tokio::net::TcpStream>,
}

struct QuicProxyRelayBuffers {
    request: BytesMut,
}

struct QuicProxyResponseBuffers {
    responses: UdpRecvBatch,
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

impl QuicProxyRelayBuffers {
    fn new() -> Self {
        Self {
            request: BytesMut::with_capacity(MAX_PACKET_SIZE + 512),
        }
    }
}

impl QuicProxyResponseBuffers {
    fn new() -> Self {
        Self {
            responses: UdpRecvBatch::new(MAX_PACKET_SIZE + 512),
        }
    }
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
                buffers: Box::new(QuicProxyRelayBuffers::new()),
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
                buffers: Box::new(QuicProxyRelayBuffers::new()),
                _control: Some(association.control),
            })
        }
    }
}

impl QuicProxyRelay {
    pub(crate) fn prepare_send_payload(&mut self, payload: &[u8]) -> Result<UdpSendBatch> {
        match &self.target {
            QuicProxyRelayTarget::Direct(target) => Ok(UdpSendBatch::single(
                Bytes::copy_from_slice(payload),
                *target,
                MAX_PACKET_SIZE + 512,
            )),
            QuicProxyRelayTarget::Proxy {
                relay_addr,
                host,
                port,
            } => {
                self.buffers.request.clear();
                write_socks_udp_packet(
                    &mut self.buffers.request,
                    address_ref_from_host(host),
                    *port,
                    payload,
                )?;
                Ok(UdpSendBatch::single(
                    self.buffers.request.split().freeze(),
                    *relay_addr,
                    MAX_PACKET_SIZE + 512,
                ))
            }
        }
    }

    pub(crate) fn response_relay(&self) -> QuicProxyResponseRelay {
        QuicProxyResponseRelay {
            outbound: self.outbound.clone(),
            target: self.target.clone(),
        }
    }

    pub(crate) fn outbound_socket(&self) -> &Arc<UdpSocket> {
        &self.outbound
    }
}

pub(crate) struct QuicProxyResponseRelay {
    outbound: Arc<UdpSocket>,
    target: QuicProxyRelayTarget,
}

pub(crate) fn relay_quic_proxy_responses(
    server_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    relay: QuicProxyResponseRelay,
) -> QuicProxyResponseDriver {
    QuicProxyResponseDriver::new(server_socket, client_addr, relay)
}

pin_project! {
    pub(crate) struct QuicProxyResponseDriver {
        server_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        relay: QuicProxyResponseRelay,
        buffers: Box<QuicProxyResponseBuffers>,
        pending: VecDeque<UdpSendBatch>,
    }
}

impl QuicProxyResponseDriver {
    fn new(
        server_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        relay: QuicProxyResponseRelay,
    ) -> Self {
        Self {
            server_socket,
            client_addr,
            relay,
            buffers: Box::new(QuicProxyResponseBuffers::new()),
            pending: VecDeque::new(),
        }
    }
}

impl Future for QuicProxyResponseDriver {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        loop {
            if let Some(send) = this.pending.front_mut() {
                ready!(send.poll_send(this.server_socket, cx))?;
                this.pending.pop_front();
                continue;
            }

            let count = ready!(
                this.buffers
                    .responses
                    .poll_recv_from(&this.relay.outbound, cx)
            )?;
            for index in 0..count {
                let Some(response) = this.buffers.responses.get(index) else {
                    continue;
                };
                let peer = response.peer();
                if response.is_oversized() {
                    tracing::debug!("ignored oversized quic proxy response");
                    continue;
                }
                match &this.relay.target {
                    QuicProxyRelayTarget::Direct(target) => {
                        if peer != *target {
                            tracing::debug!(%peer, target = %target, "ignored quic proxy response from unexpected peer");
                            continue;
                        }
                        this.pending.push_back(UdpSendBatch::single(
                            Bytes::copy_from_slice(response.payload()),
                            *this.client_addr,
                            MAX_PACKET_SIZE + 512,
                        ));
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
                        this.pending.push_back(UdpSendBatch::single(
                            Bytes::copy_from_slice(packet.payload),
                            *this.client_addr,
                            MAX_PACKET_SIZE + 512,
                        ));
                    }
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

const fn relay_bind_ip(relay_addr: SocketAddr) -> IpAddr {
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

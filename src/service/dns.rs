//! Shared DNS resolution backed by hickory-resolver's caching system resolver.
//!
//! Replaces per-call `tokio::net::lookup_host` (blocking-thread getaddrinfo,
//! no cache) so hot paths like per-datagram UDP target resolution hit the
//! in-process cache instead of issuing a fresh query for every packet.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig,
};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, ResolverBuilder, TokioResolver};

use crate::error::{Error, Result};

const DNS_CACHE_SIZE: u64 = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnsIpPreference {
    #[default]
    Default,
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

impl DnsIpPreference {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "default" => Some(Self::Default),
            "prefer-ipv4" => Some(Self::PreferIpv4),
            "prefer-ipv6" => Some(Self::PreferIpv6),
            "ipv4-only" => Some(Self::Ipv4Only),
            "ipv6-only" => Some(Self::Ipv6Only),
            _ => None,
        }
    }

    pub(crate) fn select_addrs(
        self,
        addrs: impl IntoIterator<Item = SocketAddr>,
        ipv6_enabled: bool,
    ) -> Vec<SocketAddr> {
        let addrs = addrs.into_iter().collect::<Vec<_>>();
        if self == Self::Default {
            return addrs
                .into_iter()
                .filter(|addr| ipv6_enabled || addr.is_ipv4())
                .collect();
        }

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for addr in addrs {
            match addr.ip() {
                IpAddr::V4(_) => v4.push(addr),
                IpAddr::V6(_) if ipv6_enabled => v6.push(addr),
                IpAddr::V6(_) => {}
            }
        }

        match self {
            Self::Default => unreachable!("default returns before sorting"),
            Self::PreferIpv4 => {
                v4.extend(v6);
                v4
            }
            Self::PreferIpv6 => {
                v6.extend(v4);
                v6
            }
            Self::Ipv4Only => v4,
            Self::Ipv6Only => v6,
        }
    }
}

#[derive(Clone)]
pub(crate) struct DnsResolver {
    resolver: ResolverSource,
}

#[derive(Clone)]
enum ResolverSource {
    System(Arc<OnceLock<Arc<TokioResolver>>>),
    Ready(Arc<TokioResolver>),
}

impl DnsResolver {
    pub(crate) fn system() -> Self {
        Self {
            resolver: ResolverSource::System(Arc::new(OnceLock::new())),
        }
    }

    pub(crate) fn from_config(name_server: Option<SocketAddr>) -> Result<Self> {
        match name_server {
            Some(addr) => Ok(Self {
                resolver: ResolverSource::Ready(Arc::new(build_resolver_with_name_server(addr)?)),
            }),
            None => Ok(Self::system()),
        }
    }

    pub(crate) async fn lookup_socket_addrs(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>> {
        let lookup = self.resolver()?.lookup_ip(host).await?;
        Ok(lookup
            .iter()
            .map(move |ip| SocketAddr::new(ip, port))
            .collect())
    }

    fn resolver(&self) -> Result<Arc<TokioResolver>> {
        match &self.resolver {
            ResolverSource::Ready(resolver) => Ok(resolver.clone()),
            ResolverSource::System(slot) => {
                if let Some(resolver) = slot.get() {
                    return Ok(resolver.clone());
                }
                let resolver = Arc::new(build_system_resolver()?);
                match slot.set(resolver.clone()) {
                    Ok(()) => Ok(resolver),
                    Err(_) => slot.get().cloned().ok_or(Error::DnsUnavailable),
                }
            }
        }
    }
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.resolver {
            ResolverSource::System(_) => f.write_str("DnsResolver::System"),
            ResolverSource::Ready(_) => f.write_str("DnsResolver::Configured"),
        }
    }
}

fn build_system_resolver() -> std::result::Result<TokioResolver, NetError> {
    build_tuned(Resolver::builder_tokio()?)
}

fn build_resolver_with_name_server(
    addr: SocketAddr,
) -> std::result::Result<TokioResolver, NetError> {
    let mut udp = ConnectionConfig::udp();
    udp.port = addr.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = addr.port();

    let config = ResolverConfig::from_parts(
        None,
        Vec::new(),
        vec![NameServerConfig::new(addr.ip(), true, vec![udp, tcp])],
    );
    build_tuned(Resolver::builder_with_config(
        config,
        TokioRuntimeProvider::default(),
    ))
}

fn build_tuned(
    mut builder: ResolverBuilder<TokioRuntimeProvider>,
) -> std::result::Result<TokioResolver, NetError> {
    let options = builder.options_mut();
    // Query A and AAAA together; callers filter families per their ipv6 flag.
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.cache_size = DNS_CACHE_SIZE;
    builder.build()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use super::{DnsIpPreference, DnsResolver};

    #[test]
    fn dns_ip_preference_selects_and_orders_addresses() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let v4_alt = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 443);
        let v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443);

        assert_eq!(
            DnsIpPreference::Default.select_addrs([v6, v4, v4_alt], true),
            vec![v6, v4, v4_alt]
        );
        assert_eq!(
            DnsIpPreference::Default.select_addrs([v6, v4], false),
            vec![v4]
        );
        assert_eq!(
            DnsIpPreference::PreferIpv4.select_addrs([v6, v4, v4_alt], true),
            vec![v4, v4_alt, v6]
        );
        assert_eq!(
            DnsIpPreference::PreferIpv6.select_addrs([v4, v6, v4_alt], true),
            vec![v6, v4, v4_alt]
        );
        assert_eq!(
            DnsIpPreference::Ipv4Only.select_addrs([v6, v4], true),
            vec![v4]
        );
        assert_eq!(
            DnsIpPreference::Ipv6Only.select_addrs([v4, v6], true),
            vec![v6]
        );
        assert!(
            DnsIpPreference::Ipv6Only
                .select_addrs([v4, v6], false)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn configured_resolvers_are_instance_scoped() {
        let first = DnsFixture::start(Ipv4Addr::new(127, 0, 0, 11)).await;
        let second = DnsFixture::start(Ipv4Addr::new(127, 0, 0, 22)).await;
        let first_resolver = DnsResolver::from_config(Some(first.addr)).unwrap();
        let second_resolver = DnsResolver::from_config(Some(second.addr)).unwrap();

        let first_addrs = first_resolver
            .lookup_socket_addrs("example.test", 443)
            .await
            .unwrap();
        let second_addrs = second_resolver
            .lookup_socket_addrs("example.test", 443)
            .await
            .unwrap();

        assert!(first_addrs.contains(&SocketAddr::new(IpAddr::V4(first.answer), 443)));
        assert!(second_addrs.contains(&SocketAddr::new(IpAddr::V4(second.answer), 443)));
    }

    struct DnsFixture {
        addr: SocketAddr,
        answer: Ipv4Addr,
        shutdown: CancellationToken,
        task: JoinHandle<()>,
    }

    impl DnsFixture {
        async fn start(answer: Ipv4Addr) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let shutdown = CancellationToken::new();
            let task = tokio::spawn(run_dns_fixture(socket, answer, shutdown.clone()));
            Self {
                addr,
                answer,
                shutdown,
                task,
            }
        }
    }

    impl Drop for DnsFixture {
        fn drop(&mut self) {
            self.shutdown.cancel();
            self.task.abort();
        }
    }

    async fn run_dns_fixture(socket: UdpSocket, answer: Ipv4Addr, shutdown: CancellationToken) {
        let mut buf = [0; 512];
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                result = socket.recv_from(&mut buf) => {
                    let Ok((n, peer)) = result else {
                        break;
                    };
                    if let Some(response) = dns_response(&buf[..n], answer) {
                        let _ = socket.send_to(&response, peer).await;
                    }
                }
            }
        }
    }

    fn dns_response(query: &[u8], answer: Ipv4Addr) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let question_end = dns_question_end(query)?;
        if question_end + 4 > query.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([query[question_end], query[question_end + 1]]);
        let answer_count = u16::from(qtype == 1);

        let mut response = Vec::with_capacity(query.len() + 32);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(&answer_count.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&query[12..question_end + 4]);

        if qtype == 1 {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&[0x00, 0x01]);
            response.extend_from_slice(&[0x00, 0x01]);
            response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            response.extend_from_slice(&[0x00, 0x04]);
            response.extend_from_slice(&answer.octets());
        }
        Some(response)
    }

    fn dns_question_end(query: &[u8]) -> Option<usize> {
        let mut offset = 12;
        loop {
            let len = *query.get(offset)? as usize;
            offset += 1;
            if len == 0 {
                return Some(offset);
            }
            offset = offset.checked_add(len)?;
            if offset > query.len() {
                return None;
            }
        }
    }
}

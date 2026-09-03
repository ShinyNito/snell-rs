//! Async DNS via hickory-resolver. System configuration, fail-closed.
//! `UdpLimits.dns_max` / `dns_ttl` map to Hickory `cache_size` / `positive_max_ttl`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::LookupIpStrategy;

use crate::error::SessionError;

const DNS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub struct DnsResolver {
    resolver: TokioResolver,
}

impl DnsResolver {
    pub fn try_from_system(dns_max: usize, dns_ttl: Duration) -> Result<Self, SessionError> {
        let mut builder = TokioResolver::builder_tokio()
            .map_err(|error| SessionError::Io(std::io::Error::other(error)))?;
        {
            let opts = builder.options_mut();
            opts.cache_size = dns_max as u64;
            opts.positive_max_ttl = Some(dns_ttl);
            opts.negative_max_ttl = Some(Duration::from_secs(10));
            opts.timeout = DNS_TIMEOUT;
            opts.attempts = 1;
            opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        }
        let resolver = builder
            .build()
            .map_err(|error| SessionError::Io(std::io::Error::other(error)))?;
        Ok(Self { resolver })
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, SessionError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let response = tokio::time::timeout(DNS_TIMEOUT, self.resolver.lookup_ip(host))
            .await
            .map_err(|_| {
                SessionError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "dns query timed out",
                ))
            })?
            .map_err(|error| {
                SessionError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("dns query failed: {error}"),
                ))
            })?;
        let ip = response.iter().next().ok_or_else(|| {
            SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "dns query returned empty address set",
            ))
        })?;
        Ok(SocketAddr::new(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn ip_literal_skips_lookup() {
        let dns = DnsResolver::try_from_system(1024, Duration::from_secs(30)).unwrap();
        assert_eq!(
            dns.resolve("127.0.0.1", 9).await.unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 9))
        );
        assert_eq!(
            dns.resolve("::1", 9).await.unwrap(),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 9))
        );
    }
}

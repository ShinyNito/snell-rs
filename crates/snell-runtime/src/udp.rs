//! UDP limits, metrics, and resolver shared by the client relay and the
//! server's associations.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use snell_protocol::UDP_ASSOCIATION_IDLE_SECS;

use crate::dns::DnsResolver;
use crate::error::SessionError;

const UDP_ASSOCIATION_MAX: usize = 256;
const UDP_CONTROL_MAX: usize = 256;
const UDP_QUEUE_MAX: usize = 16;
const UDP_POOL_MAX_BUFS: usize = 64;
const UDP_POOL_MAX_BYTES: usize = 4 * 1024 * 1024;
const UDP_DNS_CACHE_MAX: usize = 1024;
const UDP_DNS_CACHE_TTL_SECS: u64 = 30;

#[derive(Clone, Copy, Debug)]
pub struct UdpLimits {
    pub max_associations: usize,
    pub max_controls: usize,
    pub queue_max: usize,
    pub pool_bufs: usize,
    pub pool_bytes: usize,
    pub idle: Duration,
    pub dns_max: usize,
    pub dns_ttl: Duration,
}

impl Default for UdpLimits {
    fn default() -> Self {
        Self {
            max_associations: UDP_ASSOCIATION_MAX,
            max_controls: UDP_CONTROL_MAX,
            queue_max: UDP_QUEUE_MAX,
            pool_bufs: UDP_POOL_MAX_BUFS,
            pool_bytes: UDP_POOL_MAX_BYTES,
            idle: Duration::from_secs(UDP_ASSOCIATION_IDLE_SECS),
            dns_max: UDP_DNS_CACHE_MAX,
            dns_ttl: Duration::from_secs(UDP_DNS_CACHE_TTL_SECS),
        }
    }
}

/// Relaxed counters; `Debug` prints their current values.
#[derive(Debug, Default)]
pub struct UdpMetrics {
    pub queue_full: AtomicU64,
    pub no_buffer: AtomicU64,
    pub frag_dropped: AtomicU64,
    pub oversize: AtomicU64,
    pub map_full: AtomicU64,
    pub invalid: AtomicU64,
    pub idle_expired: AtomicU64,
    pub associations: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct UdpOptions {
    pub limits: UdpLimits,
    pub metrics: Arc<UdpMetrics>,
    pub dns: DnsResolver,
}

impl UdpOptions {
    /// Default limits, fresh metrics, and a resolver from the system DNS
    /// configuration.
    pub fn new() -> Result<Self, SessionError> {
        let limits = UdpLimits::default();
        Ok(Self {
            dns: DnsResolver::try_from_system(limits.dns_max, limits.dns_ttl)?,
            metrics: Arc::new(UdpMetrics::default()),
            limits,
        })
    }
}

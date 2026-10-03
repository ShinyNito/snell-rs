//! UDP limits, metrics, and resolver shared by the client's SOCKS5 UDP
//! associations and the server's Snell UDP sessions.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use snell_protocol::UDP_ASSOCIATION_IDLE_SECS;

use crate::dns::DnsResolver;
use crate::error::SessionError;

const UDP_ASSOCIATION_MAX: usize = 256;
const UDP_CONTROL_MAX: usize = 256;
const UDP_DNS_CACHE_MAX: usize = 1024;
const UDP_DNS_CACHE_TTL_SECS: u64 = 30;

#[derive(Clone, Copy, Debug)]
pub struct UdpLimits {
    /// Live Snell UDP sessions, on the server and on the client.
    pub max_associations: usize,
    /// Open SOCKS5 UDP ASSOCIATE control connections on the client.
    pub max_controls: usize,
    /// A session that relays nothing for this long is closed.
    pub idle: Duration,
    pub dns_max: usize,
    pub dns_ttl: Duration,
}

impl Default for UdpLimits {
    fn default() -> Self {
        Self {
            max_associations: UDP_ASSOCIATION_MAX,
            max_controls: UDP_CONTROL_MAX,
            idle: Duration::from_secs(UDP_ASSOCIATION_IDLE_SECS),
            dns_max: UDP_DNS_CACHE_MAX,
            dns_ttl: Duration::from_secs(UDP_DNS_CACHE_TTL_SECS),
        }
    }
}

/// Relaxed counters; `Debug` prints their current values.
#[derive(Debug, Default)]
pub struct UdpMetrics {
    pub frag_dropped: AtomicU64,
    pub oversize: AtomicU64,
    pub map_full: AtomicU64,
    pub invalid: AtomicU64,
    pub idle_expired: AtomicU64,
    pub associations: AtomicU64,
}

impl UdpMetrics {
    /// Count one more live session if fewer than `max` are live; the slot
    /// counts it out when dropped. A refusal is counted in `map_full`.
    pub(crate) fn admit(&self, max: usize) -> Option<SessionSlot<'_>> {
        let max = max as u64;
        let admitted = self
            .associations
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                (live < max).then_some(live + 1)
            });
        if admitted.is_err() {
            self.map_full.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(SessionSlot(self))
    }
}

/// One live session counted in [`UdpMetrics::associations`].
pub(crate) struct SessionSlot<'a>(&'a UdpMetrics);

impl Drop for SessionSlot<'_> {
    fn drop(&mut self) {
        self.0.associations.fetch_sub(1, Ordering::Relaxed);
    }
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

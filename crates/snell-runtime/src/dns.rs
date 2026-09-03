//! Bounded DNS cache. Lookup is by host key; expired entries are dropped on
//! that key or on insert eviction. There is no full-map scan on every packet.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::lookup_host;

use crate::error::SessionError;

struct Entry {
    ip: IpAddr,
    seen: Instant,
}

struct Inner {
    by_host: HashMap<String, Entry>,
    order: VecDeque<String>,
}

pub struct DnsCache {
    inner: Mutex<Inner>,
    cap: usize,
    ttl: Duration,
}

impl fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCache")
            .field("cap", &self.cap)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl DnsCache {
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_host: HashMap::new(),
                order: VecDeque::new(),
            }),
            cap,
            ttl,
        }
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, SessionError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        if let Some(ip) = self.get(host) {
            return Ok(SocketAddr::new(ip, port));
        }
        let mut addrs = lookup_host((host, port)).await?;
        let addr = addrs.next().ok_or_else(|| {
            SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "dns returned no addresses",
            ))
        })?;
        self.insert(host, addr.ip());
        Ok(SocketAddr::new(addr.ip(), port))
    }

    pub fn get(&self, host: &str) -> Option<IpAddr> {
        let key = host.to_ascii_lowercase();
        let now = Instant::now();
        let mut inner = self.lock();
        let (ip, seen) = {
            let entry = inner.by_host.get(&key)?;
            (entry.ip, entry.seen)
        };
        if now.duration_since(seen) >= self.ttl {
            inner.by_host.remove(&key);
            return None;
        }
        Some(ip)
    }

    pub fn insert(&self, host: &str, ip: IpAddr) {
        if self.cap == 0 {
            return;
        }
        let key = host.to_ascii_lowercase();
        let now = Instant::now();
        let mut inner = self.lock();
        if let std::collections::hash_map::Entry::Occupied(mut occupied) =
            inner.by_host.entry(key.clone())
        {
            occupied.insert(Entry { ip, seen: now });
            return;
        }
        while inner.by_host.len() >= self.cap {
            if let Some(old) = inner.order.pop_front() {
                inner.by_host.remove(&old);
            } else {
                break;
            }
        }
        inner.by_host.insert(key.clone(), Entry { ip, seen: now });
        inner.order.push_back(key);
    }

    pub fn len(&self) -> usize {
        self.lock().by_host.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;

    #[test]
    fn ttl_expires_only_the_looked_up_key() {
        let cache = DnsCache::new(8, Duration::from_millis(5));
        cache.insert("example.com", Ipv4Addr::LOCALHOST.into());
        cache.insert("other.test", Ipv4Addr::new(1, 2, 3, 4).into());
        thread::sleep(Duration::from_millis(10));
        assert!(cache.get("example.com").is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let cache = DnsCache::new(2, Duration::from_secs(60));
        cache.insert("a.test", Ipv4Addr::new(1, 0, 0, 1).into());
        cache.insert("b.test", Ipv4Addr::new(1, 0, 0, 2).into());
        cache.insert("c.test", Ipv4Addr::new(1, 0, 0, 3).into());
        assert_eq!(cache.len(), 2);
        assert!(cache.get("a.test").is_none());
        assert_eq!(
            cache.get("c.test"),
            Some(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 3)))
        );
    }

    #[test]
    fn get_is_keyed_hash_lookup() {
        let cache = DnsCache::new(64, Duration::from_secs(60));
        for i in 0..50 {
            cache.insert(
                &format!("h{i}.test"),
                Ipv4Addr::new(10, 0, 0, i as u8).into(),
            );
        }
        assert_eq!(
            cache.get("h7.test"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
        );
    }
}

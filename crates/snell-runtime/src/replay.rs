use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use snell_protocol::{REPLAY_CACHE_CAPACITY, REPLAY_CACHE_TTL_SECS, SALT_LEN};

use crate::error::SessionError;

/// Bounded v6 salt replay cache. Duplicate salt is a local close, not FS.
pub(crate) struct ReplayCache {
    inner: Mutex<Inner>,
    cap: usize,
    ttl: Duration,
}

struct Inner {
    by_salt: HashMap<[u8; SALT_LEN], Instant>,
    order: VecDeque<([u8; SALT_LEN], Instant)>,
}

impl ReplayCache {
    pub(crate) fn new() -> Self {
        Self::with_limits(
            REPLAY_CACHE_CAPACITY,
            Duration::from_secs(REPLAY_CACHE_TTL_SECS),
        )
    }

    pub(crate) fn with_limits(cap: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_salt: HashMap::new(),
                order: VecDeque::new(),
            }),
            cap,
            ttl,
        }
    }

    pub(crate) fn insert(&self, salt: [u8; SALT_LEN]) -> Result<(), SessionError> {
        let now = Instant::now();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        expire(&mut inner, now, self.ttl);
        if inner
            .by_salt
            .get(&salt)
            .is_some_and(|seen| now.duration_since(*seen) < self.ttl)
        {
            return Err(SessionError::ReplayDuplicate);
        }
        while inner.by_salt.len() >= self.cap && self.cap > 0 {
            if let Some((old, _)) = inner.order.pop_front() {
                inner.by_salt.remove(&old);
            } else {
                break;
            }
        }
        if self.cap == 0 {
            return Ok(());
        }
        inner.by_salt.insert(salt, now);
        inner.order.push_back((salt, now));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .by_salt
            .len()
    }
}

fn expire(inner: &mut Inner, now: Instant, ttl: Duration) {
    while let Some((salt, seen)) = inner.order.front().copied() {
        if now.duration_since(seen) >= ttl {
            inner.order.pop_front();
            if inner.by_salt.get(&salt).copied() == Some(seen) {
                inner.by_salt.remove(&salt);
            }
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn duplicate_salt_is_rejected() {
        let cache = ReplayCache::with_limits(8, Duration::from_secs(60));
        let salt = [1u8; SALT_LEN];
        cache.insert(salt).unwrap();
        assert!(matches!(
            cache.insert(salt),
            Err(SessionError::ReplayDuplicate)
        ));
    }

    #[test]
    fn capacity_evicts_oldest() {
        let cache = ReplayCache::with_limits(2, Duration::from_secs(60));
        cache.insert([1u8; SALT_LEN]).unwrap();
        cache.insert([2u8; SALT_LEN]).unwrap();
        assert_eq!(cache.len(), 2);
        cache.insert([3u8; SALT_LEN]).unwrap();
        assert_eq!(cache.len(), 2);
        cache.insert([1u8; SALT_LEN]).unwrap();
        assert!(matches!(
            cache.insert([3u8; SALT_LEN]),
            Err(SessionError::ReplayDuplicate)
        ));
    }

    #[test]
    fn concurrent_insert_of_same_salt_is_one_success() {
        let cache = Arc::new(ReplayCache::with_limits(64, Duration::from_secs(60)));
        let salt = [9u8; SALT_LEN];
        let mut joins = Vec::new();
        for _ in 0..32 {
            let cache = cache.clone();
            joins.push(thread::spawn(move || cache.insert(salt)));
        }
        let mut ok = 0usize;
        let mut dup = 0usize;
        for join in joins {
            match join.join().unwrap() {
                Ok(()) => ok += 1,
                Err(SessionError::ReplayDuplicate) => dup += 1,
                Err(other) => panic!("{other}"),
            }
        }
        assert_eq!(ok, 1);
        assert_eq!(dup, 31);
        assert_eq!(cache.len(), 1);
    }
}

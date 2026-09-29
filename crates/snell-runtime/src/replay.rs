use std::collections::{HashSet, VecDeque};
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

/// `order` holds every live salt once, oldest first; `seen` indexes it.
struct Inner {
    seen: HashSet<[u8; SALT_LEN]>,
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
                seen: HashSet::with_capacity(cap),
                order: VecDeque::with_capacity(cap),
            }),
            cap,
            ttl,
        }
    }

    pub(crate) fn insert(&self, salt: [u8; SALT_LEN]) -> Result<(), SessionError> {
        if self.cap == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let mut inner = self.lock();
        // Expire first: every salt still indexed afterwards is within the TTL.
        while let Some(&(old, seen)) = inner.order.front()
            && now.duration_since(seen) >= self.ttl
        {
            inner.order.pop_front();
            inner.seen.remove(&old);
        }
        if !inner.seen.insert(salt) {
            return Err(SessionError::ReplayDuplicate);
        }
        if inner.order.len() == self.cap
            && let Some((oldest, _)) = inner.order.pop_front()
        {
            inner.seen.remove(&oldest);
        }
        inner.order.push_back((salt, now));
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().seen.len()
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

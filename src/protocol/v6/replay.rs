use super::{Arc, Error, HashSet, Mutex, Result, SALT_SIZE, V6_SALT_REPLAY_CACHE_CAPACITY};

#[derive(Clone, Debug)]
pub struct V6SaltReplayCache {
    inner: Arc<Mutex<V6SaltReplayCacheInner>>,
}

#[derive(Debug)]
struct V6SaltReplayCacheInner {
    salts: HashSet<[u8; SALT_SIZE]>,
    ring: Vec<[u8; SALT_SIZE]>,
    next: usize,
}

impl V6SaltReplayCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(V6SaltReplayCacheInner {
                salts: HashSet::with_capacity(capacity),
                ring: vec![[0; SALT_SIZE]; capacity],
                next: 0,
            })),
        }
    }

    /// Records a salt and rejects recent replays.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt is already present in the replay cache.
    pub fn remember(&self, salt: [u8; SALT_SIZE]) -> Result<()> {
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if inner.salts.contains(&salt) {
                return Err(Error::SaltReplay);
            }

            if inner.salts.len() == inner.ring.len() {
                let oldest = inner.ring[inner.next];
                inner.salts.remove(&oldest);
            }
            inner.salts.insert(salt);
            let next = inner.next;
            inner.ring[next] = salt;
            inner.next = (next + 1) % inner.ring.len();
        }
        Ok(())
    }
}

impl Default for V6SaltReplayCache {
    fn default() -> Self {
        Self::new(V6_SALT_REPLAY_CACHE_CAPACITY)
    }
}

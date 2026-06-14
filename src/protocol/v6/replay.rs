use super::*;

#[derive(Clone, Debug)]
pub struct V6SaltReplayCache {
    inner: Arc<Mutex<V6SaltReplayCacheInner>>,
}

#[derive(Debug)]
struct V6SaltReplayCacheInner {
    capacity: usize,
    salts: HashSet<[u8; SALT_SIZE]>,
    order: VecDeque<[u8; SALT_SIZE]>,
}

impl V6SaltReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(V6SaltReplayCacheInner {
                capacity: capacity.max(1),
                salts: HashSet::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub fn remember(&self, salt: [u8; SALT_SIZE]) -> Result<()> {
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if inner.salts.contains(&salt) {
                return Err(Error::SaltReplay);
            }

            if inner.salts.len() == inner.capacity
                && let Some(oldest) = inner.order.pop_front()
            {
                inner.salts.remove(&oldest);
            }
            inner.salts.insert(salt);
            inner.order.push_back(salt);
        }
        Ok(())
    }
}

impl Default for V6SaltReplayCache {
    fn default() -> Self {
        Self::new(V6_SALT_REPLAY_CACHE_CAPACITY)
    }
}

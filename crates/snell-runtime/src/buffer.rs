use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use snell_protocol::{Buffer, Error};

use crate::SessionError;

// Growth granularity only; cache entries have no size-class identity.
const CLASSES: [usize; 12] = [
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 73728,
];

const SHARDS: usize = 4;
const CACHED_BLOCKS: usize = 64;
const MAX_CACHED_CAPACITY: usize = 73728;

#[repr(align(128))]
struct Shard(crossbeam_queue::ArrayQueue<Vec<u8>>);

/// A bounded cache of exclusive buffers. In-flight leases are limited by
/// connection admission and UDP quotas, never by cache availability.
pub struct BufferPool {
    shards: [Shard; SHARDS],
    next: AtomicUsize,
    leased_bytes: AtomicUsize,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| {
                Shard(crossbeam_queue::ArrayQueue::new(CACHED_BLOCKS / SHARDS))
            }),
            next: AtomicUsize::new(0),
            leased_bytes: AtomicUsize::new(0),
        }
    }
}

impl std::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("leased_bytes", &self.leased_bytes())
            .finish()
    }
}

impl BufferPool {
    /// Sum of live backing capacities, excluding allocator overhead and cache.
    pub fn leased_bytes(&self) -> usize {
        self.leased_bytes.load(Ordering::Relaxed)
    }

    pub(crate) fn get(self: &Arc<Self>, max: usize) -> PooledBuffer {
        let shard = self.next.fetch_add(1, Ordering::Relaxed) % SHARDS;
        let storage = self.shards[shard].0.pop().unwrap_or_default();
        self.leased_bytes
            .fetch_add(storage.capacity(), Ordering::Relaxed);
        let mut buffer = Buffer::empty(max);
        buffer
            .replace_storage(storage)
            .expect("empty buffer accepts storage");
        PooledBuffer {
            buffer,
            pool: Arc::clone(self),
            shard: Some(shard),
        }
    }

    pub(crate) fn get_empty(self: &Arc<Self>, max: usize) -> PooledBuffer {
        PooledBuffer {
            buffer: Buffer::empty(max),
            pool: Arc::clone(self),
            shard: None,
        }
    }

    fn put(&self, mut storage: Vec<u8>, shard: usize) {
        let capacity = storage.capacity();
        if capacity == 0 {
            return;
        }
        storage.clear();
        if capacity <= MAX_CACHED_CAPACITY {
            let _ = self.shards[shard].0.push(storage);
        }
        self.leased_bytes.fetch_sub(capacity, Ordering::Relaxed);
    }
}

/// An exclusive processing lease. Return it after the batch is consumed;
/// only incomplete records or pending writes retain backing storage.
pub(crate) struct PooledBuffer {
    buffer: Buffer,
    pool: Arc<BufferPool>,
    shard: Option<usize>,
}

impl PooledBuffer {
    pub(crate) fn ensure(&mut self, needed: usize) -> Result<(), SessionError> {
        if needed > self.max() {
            return Err(Error::PayloadTooLarge.into());
        }
        if self.capacity() >= needed {
            return Ok(());
        }
        if self.shard.is_none() {
            let mut lease = self.pool.get(self.max());
            std::mem::swap(self, &mut lease);
            if self.capacity() >= needed {
                return Ok(());
            }
        }
        let capacity = CLASSES
            .iter()
            .copied()
            .find(|&n| n >= needed)
            .ok_or(Error::PayloadTooLarge)?;
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(capacity)
            .map_err(|e| SessionError::Io(std::io::Error::other(e)))?;
        self.pool
            .leased_bytes
            .fetch_add(storage.capacity(), Ordering::Relaxed);
        let previous = self
            .buffer
            .replace_storage(storage)
            .expect("growth preserves live bytes");
        // Growing a live batch does not populate the cache with its old capacity.
        self.pool
            .leased_bytes
            .fetch_sub(previous.capacity(), Ordering::Relaxed);
        drop(previous);
        Ok(())
    }

    pub(crate) fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    pub(crate) fn release_empty(&mut self) {
        if let Some(storage) = self.buffer.take_empty_storage()
            && let Some(shard) = self.shard.take()
        {
            self.pool.put(storage, shard);
        }
    }

    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        let needed = self
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::PayloadTooLarge)?;
        self.ensure(needed)?;
        self.buffer.extend_from_slice(bytes)?;
        Ok(())
    }
}

impl Deref for PooledBuffer {
    type Target = Buffer;
    fn deref(&self) -> &Buffer {
        &self.buffer
    }
}
impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Buffer {
        &mut self.buffer
    }
}
impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let buffer = std::mem::replace(&mut self.buffer, Buffer::empty(0));
        if let Some(shard) = self.shard {
            self.pool.put(buffer.into_storage(), shard);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_cache_clears_returned_storage() {
        let pool = Arc::new(BufferPool::default());
        let mut leases: Vec<_> = (0..CACHED_BLOCKS + SHARDS)
            .map(|_| pool.get(snell_protocol::V6_WIRE_CAP))
            .collect();
        for lease in &mut leases {
            lease.extend(b"old payload").unwrap();
        }
        drop(leases);
        assert_eq!(pool.leased_bytes(), 0);
        assert_eq!(
            pool.shards.iter().map(|s| s.0.len()).sum::<usize>(),
            CACHED_BLOCKS
        );
        for _ in 0..CACHED_BLOCKS {
            let lease = pool.get(snell_protocol::V6_WIRE_CAP);
            assert_eq!(lease.capacity(), 64);
            assert!(lease.is_empty());
        }
        assert_eq!(pool.leased_bytes(), 0);
    }

    #[test]
    fn dirty_drop_and_growth_preserve_only_live_bytes() {
        let pool = Arc::new(BufferPool::default());
        {
            let mut a = pool.get(1024);
            a.extend(&[0x55; 64]).unwrap();
        }
        assert_eq!(pool.leased_bytes(), 0);
        let mut b = pool.get(1024);
        b.ensure(0).unwrap();
        assert_eq!(b.capacity(), 0);
        b.ensure(64).unwrap();
        assert!(b.ensure(1025).is_err());
        assert!(b.is_empty());
        b.extend(b"abcd").unwrap();
        b.consume(2).unwrap();
        b.ensure(256).unwrap();
        assert_eq!(b.filled(), b"cd");
        b.release_empty();
        assert_eq!(b.capacity(), 256);
        b.consume(2).unwrap();
        b.release_empty();
        assert_eq!(b.capacity(), 0);
        assert_eq!(pool.leased_bytes(), 0);
    }
}

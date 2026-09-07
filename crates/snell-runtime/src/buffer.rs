use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use snell_protocol::{Buffer, Error};

use crate::SessionError;

const CLASSES: [usize; 12] = [
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 73728,
];

#[derive(Clone, Copy, Debug)]
pub struct BufferLimits {
    pub total_bytes: usize,
    pub cached_bytes: usize,
    /// Maximum cached blocks in each capacity class.
    pub cached_blocks_per_class: usize,
}

impl Default for BufferLimits {
    fn default() -> Self {
        Self {
            total_bytes: 64 << 20,
            cached_bytes: 2 << 20,
            cached_blocks_per_class: 16,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferStats {
    pub allocated_bytes: usize,
    pub leased_bytes: usize,
    pub cached_bytes: usize,
    pub allocating_bytes: usize,
    pub cached_blocks: usize,
    pub hits: u64,
    pub misses: u64,
    pub rejected: u64,
}

struct State {
    free: [Vec<Vec<u8>>; 12],
    stats: BufferStats,
}

/// Shared backing allocator. Leases own bytes exclusively; free lists never
/// contain a pool handle. All counters are read under the same lock.
// ponytail: one accounting lock; shard only if concurrent benchmarks show contention.
pub struct BufferPool {
    state: Mutex<State>,
    limits: BufferLimits,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(BufferLimits::default())
    }
}

impl std::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("stats", &self.stats())
            .finish()
    }
}

impl BufferPool {
    pub fn new(limits: BufferLimits) -> Self {
        Self {
            state: Mutex::new(State {
                free: std::array::from_fn(|_| Vec::new()),
                stats: BufferStats::default(),
            }),
            limits,
        }
    }

    pub fn stats(&self) -> BufferStats {
        self.state.lock().expect("buffer pool lock").stats
    }

    fn take(&self, needed: usize) -> Result<Vec<u8>, SessionError> {
        if needed == 0 {
            return Ok(Vec::new());
        }
        let class = CLASSES
            .iter()
            .position(|&n| n >= needed)
            .ok_or(Error::PayloadTooLarge)?;
        let capacity = CLASSES[class];
        loop {
            let mut state = self.state.lock().expect("buffer pool lock");
            if let Some(block) = state.free[class].pop() {
                let n = block.capacity();
                state.stats.cached_bytes -= n;
                state.stats.cached_blocks -= 1;
                state.stats.leased_bytes += n;
                state.stats.hits += 1;
                return Ok(block);
            }
            if capacity
                <= self
                    .limits
                    .total_bytes
                    .saturating_sub(state.stats.allocated_bytes)
            {
                state.stats.allocated_bytes += capacity;
                state.stats.allocating_bytes += capacity;
                state.stats.misses += 1;
                break;
            }
            // Evict cached storage before rejecting a live request. A cache of
            // small blocks must not prevent a legal large record from progressing.
            let block = state.free.iter_mut().rev().find_map(Vec::pop);
            if let Some(block) = block {
                let n = block.capacity();
                state.stats.cached_bytes -= n;
                state.stats.cached_blocks -= 1;
                state.stats.allocated_bytes -= n;
                drop(state);
                drop(block);
            } else {
                state.stats.rejected += 1;
                return Err(SessionError::BufferBudgetExceeded);
            }
        }
        // No lock during allocation. Reserving first includes concurrent misses
        // and old+new storage during a grow in the total budget.
        let mut storage = Vec::new();
        let allocation = storage.try_reserve_exact(capacity);
        let mut state = self.state.lock().expect("buffer pool lock");
        state.stats.allocating_bytes -= capacity;
        state.stats.allocated_bytes -= capacity;
        allocation.map_err(|e| SessionError::Io(std::io::Error::other(e)))?;
        let actual = storage.capacity();
        if actual
            > self
                .limits
                .total_bytes
                .saturating_sub(state.stats.allocated_bytes)
        {
            state.stats.rejected += 1;
            drop(state);
            return Err(SessionError::BufferBudgetExceeded);
        }
        state.stats.allocated_bytes += actual;
        state.stats.leased_bytes += actual;
        Ok(storage)
    }

    fn put(&self, mut storage: Vec<u8>) {
        let capacity = storage.capacity();
        if capacity == 0 {
            return;
        }
        storage.clear(); // Old initialized bytes never become current readable bytes.
        let mut state = self.state.lock().expect("buffer pool lock");
        state.stats.leased_bytes -= capacity;
        if let Some(class) = CLASSES.iter().position(|&n| n == capacity)
            && state.free[class].len() < self.limits.cached_blocks_per_class
            && capacity
                <= self
                    .limits
                    .cached_bytes
                    .saturating_sub(state.stats.cached_bytes)
        {
            state.stats.cached_bytes += capacity;
            state.stats.cached_blocks += 1;
            state.free[class].push(storage);
        } else {
            state.stats.allocated_bytes -= capacity;
            drop(state);
            drop(storage);
        }
    }
}

/// An empty owner has no allocation. The buffer and pool handle remain valid
/// when storage is returned, so callers need no Option state machine.
pub(crate) struct OwnedBuffer {
    buffer: Buffer,
    pool: Arc<BufferPool>,
}

impl OwnedBuffer {
    pub(crate) fn new(pool: &Arc<BufferPool>, max: usize) -> Self {
        Self {
            buffer: Buffer::empty(max),
            pool: Arc::clone(pool),
        }
    }

    pub(crate) fn ensure(&mut self, needed: usize) -> Result<(), SessionError> {
        if needed > self.max() {
            return Err(Error::PayloadTooLarge.into());
        }
        if self.capacity() >= needed {
            return Ok(());
        }
        let storage = self.pool.take(needed)?;
        let previous = self
            .buffer
            .replace_storage(storage)
            .expect("growth preserves live bytes");
        self.pool.put(previous);
        Ok(())
    }

    pub(crate) fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    pub(crate) fn release_empty(&mut self) {
        if let Some(storage) = self.buffer.take_empty_storage() {
            self.pool.put(storage);
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

impl Deref for OwnedBuffer {
    type Target = Buffer;
    fn deref(&self) -> &Buffer {
        &self.buffer
    }
}
impl DerefMut for OwnedBuffer {
    fn deref_mut(&mut self) -> &mut Buffer {
        &mut self.buffer
    }
}
impl Drop for OwnedBuffer {
    fn drop(&mut self) {
        let buffer = std::mem::replace(&mut self.buffer, Buffer::empty(0));
        self.pool.put(buffer.into_storage());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_drop_reuse_and_growth_preserve_only_live_bytes() {
        let pool = Arc::new(BufferPool::default());
        {
            let mut a = OwnedBuffer::new(&pool, 1024);
            a.extend(&[0x55; 64]).unwrap();
        }
        let mut b = OwnedBuffer::new(&pool, 1024);
        b.ensure(64).unwrap();
        assert!(b.is_empty());
        assert_eq!(pool.stats().hits, 1);
        b.extend(b"abcd").unwrap();
        b.consume(2).unwrap();
        b.ensure(256).unwrap();
        assert_eq!(b.filled(), b"cd");
        b.release_empty();
        assert_eq!(b.capacity(), 256);
        b.consume(2).unwrap();
        b.release_empty();
        assert_eq!(b.capacity(), 0);
        assert_eq!(pool.stats().leased_bytes, 0);
    }

    #[test]
    fn budget_counts_growth_and_evicts_wrong_classes() {
        let pool = Arc::new(BufferPool::new(BufferLimits {
            total_bytes: 256,
            ..BufferLimits::default()
        }));
        let mut a = OwnedBuffer::new(&pool, 256);
        a.extend(b"x").unwrap();
        assert!(matches!(
            a.ensure(256),
            Err(SessionError::BufferBudgetExceeded)
        ));
        assert_eq!(a.filled(), b"x");
        drop(a);
        let mut b = OwnedBuffer::new(&pool, 256);
        b.ensure(256).unwrap();
        assert_eq!(pool.stats().allocated_bytes, 256);
        assert_eq!(pool.stats().cached_bytes, 0);
        drop(b);
        let stats = pool.stats();
        assert_eq!(
            stats.allocated_bytes,
            stats.leased_bytes + stats.cached_bytes + stats.allocating_bytes
        );
    }

    #[test]
    fn each_class_keeps_its_own_cap_and_drops_excess_immediately() {
        let pool = Arc::new(BufferPool::new(BufferLimits {
            cached_blocks_per_class: 1,
            ..BufferLimits::default()
        }));
        let mut a = OwnedBuffer::new(&pool, 256);
        let mut b = OwnedBuffer::new(&pool, 256);
        let mut c = OwnedBuffer::new(&pool, 256);
        a.ensure(64).unwrap();
        b.ensure(64).unwrap();
        c.ensure(256).unwrap();
        drop(a);
        drop(b);
        assert_eq!(pool.stats().cached_bytes, 64);
        assert_eq!(pool.stats().allocated_bytes, 64 + 256);
        drop(c);
        assert_eq!(pool.stats().cached_blocks, 2);
        assert_eq!(pool.stats().cached_bytes, 64 + 256);
        assert_eq!(pool.stats().allocated_bytes, 64 + 256);
        let misses = pool.stats().misses;
        let mut a = OwnedBuffer::new(&pool, 256);
        let mut c = OwnedBuffer::new(&pool, 256);
        a.ensure(64).unwrap();
        c.ensure(256).unwrap();
        assert_eq!(pool.stats().misses, misses);
        assert_eq!(pool.stats().hits, 2);
    }

    #[test]
    fn global_cached_byte_cap_drops_excess_across_classes() {
        let pool = Arc::new(BufferPool::new(BufferLimits {
            cached_bytes: 128,
            ..BufferLimits::default()
        }));
        let mut a = OwnedBuffer::new(&pool, 256);
        let mut b = OwnedBuffer::new(&pool, 256);
        a.ensure(64).unwrap();
        b.ensure(128).unwrap();
        drop(a);
        drop(b);
        assert_eq!(pool.stats().cached_bytes, 64);
        assert_eq!(pool.stats().allocated_bytes, 64);
        assert_eq!(pool.stats().leased_bytes, 0);
        let mut a = OwnedBuffer::new(&pool, 73728);
        a.ensure(0).unwrap();
        assert_eq!(a.capacity(), 0);
        assert!(a.ensure(73729).is_err());
    }
}

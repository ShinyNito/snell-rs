//! Bounded UDP packet-buffer pool.
//!
//! Caps both buffer count and total allocated bytes. Queue paths take
//! ownership of a [`PacketBuf`]; they do not memcpy payload to enqueue.

use std::sync::Mutex;

pub(crate) struct PacketBuf {
    /// Initialized storage. Never shrinks: `truncate` moves `len`, not `data.len()`,
    /// so reusing a pooled buffer does not re-zero the tail on every datagram.
    data: Vec<u8>,
    /// Logical datagram length; always `<= data.len()`.
    len: usize,
}

impl PacketBuf {
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn spare(&mut self, min: usize) -> &mut [u8] {
        if self.data.len() < min {
            self.data.resize(min, 0);
        }
        self.len = min;
        &mut self.data[..min]
    }

    pub fn truncate(&mut self, n: usize) {
        self.len = self.len.min(n);
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn capacity(&self) -> usize {
        self.data.capacity()
    }

    #[cfg(test)]
    pub fn from_test(data: Vec<u8>) -> Self {
        let len = data.len();
        Self { data, len }
    }
}

struct Inner {
    free: Vec<PacketBuf>,
    live: usize,
    bytes: usize,
}

pub(crate) struct PacketPool {
    inner: Mutex<Inner>,
    max_bufs: usize,
    max_bytes: usize,
}

impl PacketPool {
    pub fn new(max_bufs: usize, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                free: Vec::new(),
                live: 0,
                bytes: 0,
            }),
            max_bufs,
            max_bytes,
        }
    }

    pub fn acquire(&self, min_cap: usize) -> Option<PacketBuf> {
        if min_cap == 0 {
            return Some(PacketBuf {
                data: Vec::new(),
                len: 0,
            });
        }
        let mut inner = self.lock();
        if let Some(idx) = inner.free.iter().rposition(|buf| buf.capacity() >= min_cap) {
            let buf = inner.free.swap_remove(idx);
            inner.live += 1;
            return Some(buf);
        }
        let held = inner.live + inner.free.len();
        if held >= self.max_bufs {
            return None;
        }
        let add = min_cap;
        if inner.bytes.saturating_add(add) > self.max_bytes {
            return None;
        }
        let buf = PacketBuf {
            data: Vec::with_capacity(min_cap),
            len: 0,
        };
        inner.bytes += buf.capacity();
        inner.live += 1;
        Some(buf)
    }

    pub fn release(&self, buf: PacketBuf) {
        let mut inner = self.lock();
        inner.live = inner.live.saturating_sub(1);
        let cap = buf.capacity();
        if inner.free.len() + inner.live >= self.max_bufs || inner.bytes > self.max_bytes {
            inner.bytes = inner.bytes.saturating_sub(cap);
            return;
        }
        inner.free.push(buf);
    }

    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.lock().live
    }

    #[cfg(test)]
    pub fn allocated_bufs(&self) -> usize {
        let inner = self.lock();
        inner.live + inner.free.len()
    }

    #[cfg(test)]
    pub fn allocated_bytes(&self) -> usize {
        self.lock().bytes
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

    #[test]
    fn truncate_then_spare_does_not_rezero_storage() {
        let pool = PacketPool::new(1, 1024);
        let mut buf = pool.acquire(8).unwrap();
        buf.spare(8).copy_from_slice(&[0xAA; 8]);
        buf.truncate(2);
        assert_eq!(buf.as_slice(), &[0xAA, 0xAA]);
        // The tail keeps its prior contents: reuse must not memset per datagram.
        assert_eq!(buf.spare(8), &[0xAA; 8]);
        assert_eq!(buf.len(), 8);
        pool.release(buf);
    }

    #[test]
    fn acquire_fails_at_count_cap() {
        let pool = PacketPool::new(1, 1024 * 1024);
        let a = pool.acquire(64).unwrap();
        assert!(pool.acquire(64).is_none());
        assert_eq!(pool.live(), 1);
        pool.release(a);
        assert_eq!(pool.live(), 0);
        assert!(pool.acquire(64).is_some());
    }

    #[test]
    fn acquire_fails_at_byte_cap() {
        let pool = PacketPool::new(8, 100);
        let a = pool.acquire(80).unwrap();
        assert!(pool.acquire(80).is_none());
        pool.release(a);
    }

    #[test]
    fn release_returns_buffer_without_growing_past_cap() {
        let pool = PacketPool::new(2, 1024);
        let a = pool.acquire(32).unwrap();
        let b = pool.acquire(32).unwrap();
        assert_eq!(pool.allocated_bufs(), 2);
        pool.release(a);
        pool.release(b);
        assert!(pool.allocated_bufs() <= 2);
        assert!(pool.allocated_bytes() <= 1024);
    }
}

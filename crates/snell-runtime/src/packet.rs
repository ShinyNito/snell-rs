//! Bounded UDP packet-buffer pool.
//!
//! Caps both buffer count and total allocated bytes. Queue paths take
//! ownership of a [`PacketBuf`]; they do not memcpy payload to enqueue.
//! Each checked-out buffer returns itself on drop, including cancellation.

use std::sync::{Arc, Mutex};

pub(crate) struct PacketBuf {
    /// `data.len()` is the datagram length. Fills go through [`Self::storage_mut`]
    /// (uninit append, e.g. `recv_buf_from` / `extend_from_slice`), so pooled
    /// reuse never memsets storage and only bytes actually written are dirtied.
    data: Vec<u8>,
    pool: Option<Arc<Mutex<Inner>>>,
}

impl PacketBuf {
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Cleared backing storage for an append-style fill. Callers must not
    /// write past the existing capacity ([`PacketPool::acquire`] sized it);
    /// growth would escape the pool's byte accounting.
    pub fn storage_mut(&mut self) -> &mut Vec<u8> {
        self.data.clear();
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[cfg(test)]
    pub fn from_test(data: Vec<u8>) -> Self {
        Self { data, pool: None }
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        let mut inner = pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.live -= 1;
        let mut data = std::mem::take(&mut self.data);
        data.clear();
        // Free entries are plain Vecs, not leases: no Arc ownership cycle.
        inner.free.push(data);
    }
}

struct Inner {
    free: Vec<Vec<u8>>,
    live: usize,
    bytes: usize,
}

pub(crate) struct PacketPool {
    inner: Arc<Mutex<Inner>>,
    max_bufs: usize,
    max_bytes: usize,
}

impl PacketPool {
    pub fn new(max_bufs: usize, max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                free: Vec::new(),
                live: 0,
                bytes: 0,
            })),
            max_bufs,
            max_bytes,
        }
    }

    pub fn acquire(&self, min_cap: usize) -> Option<PacketBuf> {
        if min_cap == 0 {
            return Some(PacketBuf {
                data: Vec::new(),
                pool: None,
            });
        }
        let mut inner = self.lock();
        if let Some(idx) = inner.free.iter().rposition(|buf| buf.capacity() >= min_cap) {
            let data = inner.free.swap_remove(idx);
            inner.live += 1;
            return Some(PacketBuf {
                data,
                pool: Some(self.inner.clone()),
            });
        }
        let held = inner.live + inner.free.len();
        if held >= self.max_bufs {
            return None;
        }
        if inner.bytes.saturating_add(min_cap) > self.max_bytes {
            return None;
        }
        let data = Vec::with_capacity(min_cap);
        // Charge actual capacity, not just the requested minimum.
        let bytes = inner.bytes.checked_add(data.capacity())?;
        if bytes > self.max_bytes {
            return None;
        }
        inner.bytes = bytes;
        inner.live += 1;
        Some(PacketBuf {
            data,
            pool: Some(self.inner.clone()),
        })
    }

    pub fn release(&self, buf: PacketBuf) {
        // Existing explicit-return sites and implicit error/cancel paths use
        // the same owner. Returning to a different pool cannot corrupt counts.
        drop(buf);
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
    fn storage_mut_clears_len_and_keeps_capacity() {
        let pool = PacketPool::new(1, 1024);
        let mut buf = pool.acquire(8).unwrap();
        buf.storage_mut().extend_from_slice(&[0xAA; 8]);
        assert_eq!(buf.as_slice(), &[0xAA; 8]);
        let cap = buf.storage_mut().capacity();
        assert!(cap >= 8);
        assert_eq!(buf.len(), 0, "storage_mut starts a fresh datagram");
        buf.storage_mut().extend_from_slice(&[0x55; 2]);
        pool.release(buf);
        assert_eq!(pool.live(), 0);
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

    #[test]
    fn drop_returns_buffer_without_explicit_release() {
        let pool = PacketPool::new(1, 1024);
        for _ in 0..64 {
            let buf = pool.acquire(64).unwrap();
            assert_eq!(pool.live(), 1);
            assert!(pool.acquire(64).is_none());
            drop(buf);
            assert_eq!(pool.live(), 0);
            assert_eq!(pool.allocated_bufs(), 1);
            assert_eq!(pool.allocated_bytes(), 64);
        }
    }

    #[test]
    fn dropping_queue_returns_all_leases() {
        let pool = PacketPool::new(2, 1024);
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        assert!(tx.try_send(pool.acquire(64).unwrap()).is_ok());
        assert!(tx.try_send(pool.acquire(64).unwrap()).is_ok());
        assert_eq!(pool.live(), 2);
        drop(rx);
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.allocated_bufs(), 2);
    }

    #[tokio::test]
    async fn abort_returns_in_flight_lease() {
        let pool = PacketPool::new(1, 1024);
        let buf = pool.acquire(64).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _buf = buf;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        assert_eq!(pool.live(), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(pool.live(), 0);
        assert!(pool.acquire(64).is_some());
    }

    #[test]
    fn final_lease_does_not_keep_pool_alive() {
        let pool = PacketPool::new(1, 1024);
        let weak = Arc::downgrade(&pool.inner);
        let buf = pool.acquire(64).unwrap();
        drop(pool);
        assert!(weak.upgrade().is_some());
        drop(buf);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn empty_and_test_buffers_do_not_change_pool_accounting() {
        let pool = PacketPool::new(1, 1024);
        drop(pool.acquire(0).unwrap());
        pool.release(PacketBuf::from_test(vec![1, 2, 3]));
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.allocated_bufs(), 0);
        assert_eq!(pool.allocated_bytes(), 0);
    }
}

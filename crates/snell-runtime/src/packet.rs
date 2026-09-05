//! Bounded UDP packet-buffer pool.
//!
//! Caps both buffer count and total allocated bytes. Queue paths take
//! ownership of a [`PacketBuf`]; they do not memcpy payload to enqueue.
//! Each checked-out buffer returns itself on drop, including cancellation.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use bytes::{BufMut, buf::UninitSlice};
use std::sync::{Arc, Mutex};

pub(crate) struct PacketBuf {
    /// `data.len()` is the datagram length. Fills go through [`BufMut`]
    /// (uninit append, e.g. `recv_buf_from` / `extend_from_slice`), so pooled
    /// reuse never memsets storage and only bytes actually written are dirtied.
    data: Vec<u8>,
    pool: Option<Arc<Mutex<Inner>>>,
}

impl PacketBuf {
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    #[cfg(test)]
    pub fn from_test(data: Vec<u8>) -> Self {
        Self { data, pool: None }
    }
}

// SAFETY: leases expose only the already charged tail; they cannot reallocate.
unsafe impl BufMut for PacketBuf {
    fn remaining_mut(&self) -> usize {
        self.data.capacity() - self.data.len()
    }
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        UninitSlice::uninit(self.data.spare_capacity_mut())
    }
    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining_mut(),
            "packet initialized beyond capacity"
        );
        // SAFETY: BufMut requires the caller to initialize this exact tail prefix.
        unsafe { self.data.set_len(self.data.len() + cnt) };
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
        if let Some(idx) = inner
            .free
            .iter()
            .enumerate()
            .filter(|(_, buf)| buf.capacity() >= min_cap)
            .min_by_key(|(_, buf)| buf.capacity())
            .map(|(index, _)| index)
        {
            let data = inner.free.swap_remove(idx);
            inner.live += 1;
            return Some(PacketBuf {
                data,
                pool: Some(self.inner.clone()),
            });
        }
        if min_cap > self.max_bytes || self.max_bufs == 0 {
            return None;
        }
        // Free undersized buffers must not prevent a legal larger datagram.
        // Live leases are never evicted or removed from the byte accounting.
        while inner.live + inner.free.len() >= self.max_bufs
            || inner
                .bytes
                .checked_add(min_cap)
                .is_none_or(|bytes| bytes > self.max_bytes)
        {
            let old = inner.free.pop()?;
            inner.bytes -= old.capacity();
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

    pub fn trim(&self) {
        let mut inner = self.lock();
        let freed: usize = inner.free.iter().map(Vec::capacity).sum();
        inner.free.clear();
        inner.bytes -= freed;
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
    fn clear_keeps_charged_capacity() {
        let pool = PacketPool::new(1, 1024);
        let mut buf = pool.acquire(8).unwrap();
        buf.put_slice(&[0xAA; 8]);
        assert_eq!(buf.as_slice(), &[0xAA; 8]);
        buf.clear();
        let cap = buf.remaining_mut();
        assert!(cap >= 8);
        assert_eq!(buf.as_slice().len(), 0, "clear starts a fresh datagram");
        buf.put_slice(&[0x55; 2]);
        drop(buf);
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn acquire_fails_at_count_cap() {
        let pool = PacketPool::new(1, 1024 * 1024);
        let a = pool.acquire(64).unwrap();
        assert!(pool.acquire(64).is_none());
        assert_eq!(pool.live(), 1);
        drop(a);
        assert_eq!(pool.live(), 0);
        assert!(pool.acquire(64).is_some());
    }

    #[test]
    fn acquire_fails_at_byte_cap() {
        let pool = PacketPool::new(8, 100);
        let a = pool.acquire(80).unwrap();
        assert!(pool.acquire(80).is_none());
        drop(a);
    }

    #[test]
    fn release_returns_buffer_without_growing_past_cap() {
        let pool = PacketPool::new(2, 1024);
        let a = pool.acquire(32).unwrap();
        let b = pool.acquire(32).unwrap();
        assert_eq!(pool.allocated_bufs(), 2);
        drop(a);
        drop(b);
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
        drop(PacketBuf::from_test(vec![1, 2, 3]));
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.allocated_bufs(), 0);
        assert_eq!(pool.allocated_bytes(), 0);
    }
    #[test]
    fn larger_packet_replaces_idle_small_buffers_without_exceeding_budget() {
        let pool = PacketPool::new(2, 1024);
        let a = pool.acquire(64).unwrap();
        let b = pool.acquire(64).unwrap();
        drop((a, b));
        let large = pool.acquire(512).unwrap();
        assert!(pool.allocated_bufs() <= 2);
        assert!(pool.allocated_bytes() <= 1024);
        pool.trim();
        assert_eq!(pool.allocated_bytes(), 512);
        drop(large);
        pool.trim();
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.allocated_bytes(), 0);
    }

    #[test]
    fn lease_buf_mut_is_bounded_by_its_charged_capacity() {
        let pool = PacketPool::new(1, 64);
        let mut buf = pool.acquire(64).unwrap();
        buf.put_slice(&[1; 63]);
        assert_eq!(buf.remaining_mut(), 1);
        buf.put_u8(2);
        assert_eq!(buf.remaining_mut(), 0);
        assert_eq!(buf.as_slice().len(), 64);
        assert_eq!(pool.allocated_bytes(), 64);
    }
}

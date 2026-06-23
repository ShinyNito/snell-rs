use std::{
    collections::VecDeque,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

pub const DEFAULT_MAX_AGE: Duration = Duration::from_mins(5);
pub const DEFAULT_MAX_SIZE: usize = 10;

#[derive(Debug)]
pub struct ConnectionPool<T> {
    entries: Mutex<VecDeque<PooledEntry<T>>>,
    max_age: Duration,
    max_size: usize,
}

#[derive(Debug)]
struct PooledEntry<T> {
    value: T,
    returned_at: Instant,
}

impl<T> ConnectionPool<T> {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_SIZE, DEFAULT_MAX_AGE)
    }

    pub fn with_limits(max_size: usize, max_age: Duration) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_size)),
            max_age,
            max_size,
        }
    }

    pub fn take(&self) -> Option<T> {
        let mut entries = self.entries();
        while let Some(entry) = entries.pop_front() {
            if entry.returned_at.elapsed() <= self.max_age {
                return Some(entry.value);
            }
        }
        None
    }

    pub fn put(&self, value: T) -> bool {
        if self.max_size == 0 {
            return false;
        }

        let mut entries = self.entries();
        if entries.len() >= self.max_size {
            return false;
        }

        entries.push_back(PooledEntry {
            value,
            returned_at: Instant::now(),
        });
        true
    }

    pub fn len(&self) -> usize {
        self.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.entries().clear();
    }

    fn entries(&self) -> MutexGuard<'_, VecDeque<PooledEntry<T>>> {
        // ponytail: one tiny critical section; split by upstream only if profiling says this contends.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<T> Default for ConnectionPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    #[test]
    fn takes_entries_fifo() {
        let pool = ConnectionPool::with_limits(2, Duration::from_secs(15));
        assert!(pool.put(1));
        assert!(pool.put(2));

        assert_eq!(pool.take(), Some(1));
        assert_eq!(pool.take(), Some(2));
        assert_eq!(pool.take(), None);
    }

    #[test]
    fn drops_expired_entries() {
        let drops = Arc::new(AtomicUsize::new(0));
        let pool = ConnectionPool::with_limits(1, Duration::from_millis(1));

        assert!(pool.put(DropProbe(drops.clone())));
        thread::sleep(Duration::from_millis(2));

        assert!(pool.take().is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn drops_when_full() {
        let drops = Arc::new(AtomicUsize::new(0));
        let pool = ConnectionPool::with_limits(1, Duration::from_secs(15));

        assert!(pool.put(DropProbe(drops.clone())));
        assert!(!pool.put(DropProbe(drops.clone())));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

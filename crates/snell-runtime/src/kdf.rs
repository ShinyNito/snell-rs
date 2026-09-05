use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use snell_protocol::{KDF_MAX_INFLIGHT, KDF_MAX_QUEUED};
use tokio::sync::Semaphore;

use crate::error::SessionError;

/// Bounded Argon2id gate. KDF does not run unconstrained on the reactor poll.
pub(crate) struct KdfLimiter {
    sem: Arc<Semaphore>,
    queued: AtomicUsize,
    max_queued: usize,
}

/// A waiting future may be dropped at any await point.
struct Queued<'a>(&'a AtomicUsize);

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl KdfLimiter {
    pub(crate) fn new() -> Self {
        let inflight = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, KDF_MAX_INFLIGHT);
        Self {
            sem: Arc::new(Semaphore::new(inflight)),
            queued: AtomicUsize::new(0),
            max_queued: KDF_MAX_QUEUED,
        }
    }

    pub(crate) async fn run<T, F>(&self, f: F) -> Result<T, SessionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = match self.sem.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let queued = self.queued.fetch_add(1, Ordering::SeqCst);
                let _queued = Queued(&self.queued);
                if queued >= self.max_queued {
                    return Err(SessionError::KdfQueueFull);
                }
                self.sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| SessionError::Cancelled)?
            }
        };
        // A started blocking task survives cancellation of its async waiter.
        // Keep its permit until the actual work exits, including on unwind.
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await
        .map_err(|_| SessionError::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snell_protocol::{Psk, aead_key};
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    use std::time::Duration;

    fn single_slot() -> KdfLimiter {
        KdfLimiter {
            sem: Arc::new(Semaphore::new(1)),
            queued: AtomicUsize::new(0),
            max_queued: 1,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kdf_run_matches_inline() {
        let limiter = KdfLimiter::new();
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let salt = [7u8; 16];
        let inline = aead_key(psk.as_bytes(), &salt).unwrap();
        let psk_bytes = psk.as_bytes().to_vec();
        let spawned = limiter
            .run(move || aead_key(&psk_bytes, &salt))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inline, spawned);
    }

    #[tokio::test]
    async fn cancelling_waiters_restores_queue_capacity() {
        let limiter = single_slot();
        let permit = limiter.sem.clone().acquire_owned().await.unwrap();
        for _ in 0..64 {
            let mut waiting = Box::pin(limiter.run(|| ()));
            poll_fn(|cx| {
                assert!(waiting.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(limiter.queued.load(Ordering::SeqCst), 1);
            assert!(matches!(
                limiter.run(|| ()).await,
                Err(SessionError::KdfQueueFull)
            ));
            assert_eq!(limiter.queued.load(Ordering::SeqCst), 1);
            drop(waiting);
            assert_eq!(limiter.queued.load(Ordering::SeqCst), 0);
        }
        drop(permit);
        assert_eq!(limiter.run(|| 42).await.unwrap(), 42);
        assert_eq!(limiter.sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn successful_waiter_restores_queue_capacity() {
        let limiter = single_slot();
        let permit = limiter.sem.clone().acquire_owned().await.unwrap();
        let mut waiting = Box::pin(limiter.run(|| 42));
        poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(limiter.queued.load(Ordering::SeqCst), 1);
        drop(permit);
        assert_eq!(waiting.await.unwrap(), 42);
        assert_eq!(limiter.queued.load(Ordering::SeqCst), 0);
        assert_eq!(limiter.sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelling_running_waiter_does_not_release_permit() {
        let limiter = Arc::new(single_slot());
        let running = limiter.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        // Dropping the sender also unblocks the worker if an assertion fails.
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = tokio::spawn(async move {
            running
                .run(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(limiter.sem.available_permits(), 0);
        assert!(limiter.sem.clone().try_acquire_owned().is_err());
        release_tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), limiter.run(|| 42))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, 42);
        assert_eq!(limiter.sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn panicking_work_releases_permit() {
        let limiter = single_slot();
        assert!(matches!(
            limiter.run(|| panic!("test KDF panic")).await,
            Err(SessionError::Cancelled)
        ));
        assert_eq!(limiter.sem.available_permits(), 1);
        assert_eq!(limiter.run(|| 42).await.unwrap(), 42);
    }
}

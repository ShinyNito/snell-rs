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

impl KdfLimiter {
    #[cfg(test)]
    pub(crate) fn block_for_test(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.sem
            .clone()
            .try_acquire_many_owned(self.sem.available_permits() as u32)
            .unwrap()
    }

    #[cfg(test)]
    pub(crate) fn queued_for_test(&self) -> usize {
        self.queued.load(Ordering::SeqCst)
    }

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
                if queued >= self.max_queued {
                    self.queued.fetch_sub(1, Ordering::SeqCst);
                    return Err(SessionError::KdfQueueFull);
                }
                let waiting = Waiting(&self.queued);
                let permit = self
                    .sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| SessionError::Cancelled)?;
                drop(waiting);
                permit
            }
        };
        let out = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await
        .map_err(|_| SessionError::Cancelled)?;
        Ok(out)
    }
}

struct Waiting<'a>(&'a AtomicUsize);
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snell_protocol::{Psk, aead_key};

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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_keeps_waiting_and_running_counts_exact() {
        use std::future::Future;
        use std::task::{Context, Waker};
        let limiter = Arc::new(KdfLimiter {
            sem: Arc::new(Semaphore::new(1)),
            queued: AtomicUsize::new(0),
            max_queued: 1,
        });
        let permit = limiter.sem.clone().acquire_owned().await.unwrap();
        let mut queued = Box::pin(limiter.run(|| ()));
        assert!(
            queued
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(limiter.queued.load(Ordering::SeqCst), 1);
        drop(queued);
        assert_eq!(limiter.queued.load(Ordering::SeqCst), 0);
        drop(permit);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let task_limiter = limiter.clone();
        let task = tokio::spawn(async move {
            task_limiter
                .run(move || {
                    started_tx.send(()).unwrap();
                    finish_rx.recv().unwrap();
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            limiter.sem.available_permits(),
            0,
            "blocking work still owns the permit"
        );
        finish_tx.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(2), limiter.sem.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(limiter.sem.available_permits(), 1);
    }
}

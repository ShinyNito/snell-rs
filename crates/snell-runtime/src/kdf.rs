use std::sync::Arc;

use snell_protocol::{KDF_MAX_INFLIGHT, KDF_MAX_QUEUED, Psk};
use tokio::sync::Semaphore;

use crate::error::SessionError;

/// Bounded Argon2id gate. KDF does not run unconstrained on the reactor poll.
pub(crate) struct KdfLimiter {
    running: Arc<Semaphore>,
    /// Waiting slots. A full queue fails closed instead of growing.
    queue: Semaphore,
}

impl KdfLimiter {
    #[cfg(test)]
    pub(crate) fn block_for_test(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.running)
            .try_acquire_many_owned(self.running.available_permits() as u32)
            .unwrap()
    }

    #[cfg(test)]
    pub(crate) fn queued_for_test(&self) -> usize {
        KDF_MAX_QUEUED - self.queue.available_permits()
    }

    pub(crate) fn new() -> Self {
        let inflight = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, KDF_MAX_INFLIGHT);
        Self::with_limits(inflight, KDF_MAX_QUEUED)
    }

    fn with_limits(inflight: usize, queued: usize) -> Self {
        Self {
            running: Arc::new(Semaphore::new(inflight)),
            queue: Semaphore::new(queued),
        }
    }

    /// Run one Argon2id-bound derivation (a key or a record encoder) on the
    /// blocking pool, waiting in the bounded queue when every slot is busy.
    pub(crate) async fn derive<T>(
        &self,
        psk: &Psk,
        derive: impl FnOnce(&Psk) -> snell_protocol::Result<T> + Send + 'static,
    ) -> Result<T, SessionError>
    where
        T: Send + 'static,
    {
        let permit = match Arc::clone(&self.running).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let _waiting = self
                    .queue
                    .try_acquire()
                    .map_err(|_| SessionError::KdfQueueFull)?;
                Arc::clone(&self.running)
                    .acquire_owned()
                    .await
                    .map_err(|_| SessionError::Cancelled)?
            }
        };
        let psk = psk.clone();
        let derived = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            derive(&psk)
        })
        .await
        .map_err(|_| SessionError::Cancelled)?;
        Ok(derived?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snell_protocol::aead_key;

    #[tokio::test(flavor = "multi_thread")]
    async fn kdf_derive_matches_inline() {
        let limiter = KdfLimiter::new();
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let salt = [7u8; 16];
        let inline = aead_key(&psk, &salt).unwrap();
        let spawned = limiter
            .derive(&psk, move |psk| aead_key(psk, &salt))
            .await
            .unwrap();
        assert_eq!(inline, spawned);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_keeps_waiting_and_running_counts_exact() {
        use std::future::Future;
        use std::task::{Context, Waker};
        let limiter = Arc::new(KdfLimiter::with_limits(1, 1));
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let permit = limiter.running.clone().acquire_owned().await.unwrap();
        let mut queued = Box::pin(limiter.derive(&psk, |_| Ok(())));
        assert!(
            queued
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(limiter.queue.available_permits(), 0);
        assert!(matches!(
            limiter.derive(&psk, |_| Ok(())).await,
            Err(SessionError::KdfQueueFull)
        ));
        drop(queued);
        assert_eq!(limiter.queue.available_permits(), 1);
        drop(permit);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let task_limiter = limiter.clone();
        let task = tokio::spawn(async move {
            task_limiter
                .derive(&psk, move |_| {
                    started_tx.send(()).unwrap();
                    finish_rx.recv().unwrap();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            limiter.running.available_permits(),
            0,
            "blocking work still owns the permit"
        );
        finish_tx.send(()).unwrap();
        let permit =
            tokio::time::timeout(std::time::Duration::from_secs(2), limiter.running.acquire())
                .await
                .unwrap()
                .unwrap();
        drop(permit);
        assert_eq!(limiter.running.available_permits(), 1);
    }
}

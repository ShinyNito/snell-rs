use std::sync::atomic::{AtomicUsize, Ordering};

use snell_protocol::{KDF_MAX_INFLIGHT, KDF_MAX_QUEUED};
use tokio::sync::Semaphore;

use crate::error::SessionError;

/// Bounded Argon2id gate. KDF does not run unconstrained on the reactor poll.
pub(crate) struct KdfLimiter {
    sem: Semaphore,
    queued: AtomicUsize,
    max_queued: usize,
}

impl KdfLimiter {
    pub(crate) fn new() -> Self {
        let inflight = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, KDF_MAX_INFLIGHT);
        Self {
            sem: Semaphore::new(inflight),
            queued: AtomicUsize::new(0),
            max_queued: KDF_MAX_QUEUED,
        }
    }

    pub(crate) async fn run<T, F>(&self, f: F) -> Result<T, SessionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = match self.sem.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                let queued = self.queued.fetch_add(1, Ordering::SeqCst);
                if queued >= self.max_queued {
                    self.queued.fetch_sub(1, Ordering::SeqCst);
                    return Err(SessionError::KdfQueueFull);
                }
                let permit = self
                    .sem
                    .acquire()
                    .await
                    .map_err(|_| SessionError::Cancelled)?;
                self.queued.fetch_sub(1, Ordering::SeqCst);
                permit
            }
        };
        let out = tokio::task::spawn_blocking(f)
            .await
            .map_err(|_| SessionError::Cancelled)?;
        drop(permit);
        Ok(out)
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
}

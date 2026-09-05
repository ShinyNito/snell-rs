use std::future::Future;
use std::time::Duration;

use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, timeout_at};

use crate::SessionError;

/// Per-listener resource budgets. Connections include authenticated reuse-idle
/// sessions and SOCKS5 UDP controls; handshake slots cover setup only.
#[derive(Clone, Copy, Debug)]
pub struct TcpLimits {
    pub max_connections: usize,
    pub max_handshakes: usize,
}

impl Default for TcpLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_handshakes: 64,
        }
    }
}

impl TcpLimits {
    pub(crate) fn validate(self) -> Result<(), SessionError> {
        if self.max_connections == 0
            || self.max_handshakes == 0
            || self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_handshakes > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP connection and handshake limits must be positive semaphore capacities",
            )
            .into());
        }
        Ok(())
    }
}

/// One absolute deadline from accept through KDF, connect, and the tunnel reply.
/// The owned permit is released on success, error, timeout or cancellation.
pub(crate) struct Handshake {
    deadline: Instant,
    permit: Option<OwnedSemaphorePermit>,
}

impl Handshake {
    pub(crate) fn new(permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            deadline: Instant::now()
                + Duration::from_secs(snell_protocol::TCP_HANDSHAKE_TIMEOUT_SECS),
            permit,
        }
    }

    pub(crate) fn run<T, F>(&self, future: F) -> tokio::time::Timeout<F>
    where
        F: Future<Output = Result<T, SessionError>>,
    {
        timeout_at(self.deadline, future)
    }

    pub(crate) fn finish(&mut self) {
        self.permit.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[tokio::test(start_paused = true)]
    async fn stages_share_deadline_and_cancel_returns_permit() {
        let sem = Arc::new(Semaphore::new(1));
        let handshake = Handshake::new(Some(sem.clone().acquire_owned().await.unwrap()));
        handshake
            .run(async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            })
            .await
            .unwrap()
            .unwrap();
        let result = handshake
            .run(async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            })
            .await;
        assert!(result.is_err(), "the original deadline must expire");
        assert_eq!(sem.available_permits(), 0);
        drop(handshake);
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn authenticated_session_releases_only_handshake_slot() {
        let sem = Arc::new(Semaphore::new(1));
        let mut handshake = Handshake::new(Some(sem.clone().acquire_owned().await.unwrap()));
        assert_eq!(sem.available_permits(), 0);
        handshake.finish();
        handshake.finish();
        assert_eq!(sem.available_permits(), 1);
    }

    #[test]
    fn invalid_limits_fail_before_creating_semaphores() {
        assert!(
            TcpLimits {
                max_connections: 0,
                max_handshakes: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            TcpLimits {
                max_connections: 1,
                max_handshakes: usize::MAX
            }
            .validate()
            .is_err()
        );
    }
}

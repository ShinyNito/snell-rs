use std::{future::Future, io, time::Duration};

use tokio::time;

pub(crate) const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TCP_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) async fn with_tcp_connect_timeout<F, T>(
    future: F,
    operation: &'static str,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    with_deadline(TCP_CONNECT_TIMEOUT, future, operation).await
}

pub(crate) async fn with_tcp_timeout<F, T>(future: F, operation: &'static str) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    with_deadline(TCP_TIMEOUT, future, operation).await
}

pub(crate) fn timed_out(operation: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{operation} timed out"))
}

async fn with_deadline<F, T>(
    duration: Duration,
    future: F,
    operation: &'static str,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    time::timeout(duration, future)
        .await
        .map_err(|_| timed_out(operation))?
}

#[cfg(test)]
mod tests {
    use std::{future, time::Duration};

    use super::*;

    #[test]
    fn uses_sing_box_tcp_defaults() {
        assert_eq!(TCP_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(TCP_TIMEOUT, Duration::from_secs(15));
    }

    #[tokio::test]
    async fn maps_elapsed_to_timed_out() {
        let err = with_deadline(
            Duration::from_millis(1),
            future::pending::<io::Result<()>>(),
            "test operation",
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}

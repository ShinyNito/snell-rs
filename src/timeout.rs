use std::{future::Future, io, time::Duration};

use compio::time;

pub(crate) const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TCP_TIMEOUT: Duration = Duration::from_secs(15);

/// reuse 完成一条 sub-stream 后，等下一条 S0 (`01 05 ...`) 的空闲上限。
///
/// 官方 v6 服务端在回到 stage S0 复用等待状态时启动一个 1 hour 的 idle
/// timer，触发时日志为 `Connection idle before handshake`。与首条 S0 的短
/// 超时（`Connection timeout before handshake`，10s）不同，二者独立。
pub(crate) const REUSE_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

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

pub(crate) async fn with_deadline<F, T>(
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

    #[test]
    fn reuse_idle_matches_official_one_hour() {
        // 官方 v6：reuse idle 超时为 1 hour。
        assert_eq!(REUSE_IDLE_TIMEOUT, Duration::from_secs(3600));
    }

    #[compio::test]
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

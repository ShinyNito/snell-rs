use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;

pub(crate) const SERVER_LISTEN_BACKLOG: u32 = 4096;
pub(crate) const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn bind_tcp_listener(
    listen_addr: SocketAddr,
    tcp_fast_open: bool,
) -> std::io::Result<TcpListener> {
    let socket = if listen_addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    if tcp_fast_open {
        try_enable_tcp_fast_open(&socket);
    }
    socket.bind(listen_addr)?;
    socket.listen(SERVER_LISTEN_BACKLOG)
}

#[cfg(any(
    target_os = "android",
    target_os = "cygwin",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "hurd",
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn try_enable_tcp_fast_open(socket: &TcpSocket) {
    use std::mem::size_of_val;
    use std::os::fd::AsRawFd;

    let value: libc::c_int = SERVER_LISTEN_BACKLOG.cast_signed();
    let value_len = libc::socklen_t::try_from(size_of_val(&value))
        .expect("c_int socket option length fits socklen_t");
    // SAFETY: `value` is a live c_int for the duration of the setsockopt call,
    // and the socket raw fd comes from Tokio's TcpSocket.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            (&raw const value).cast(),
            value_len,
        )
    };
    if result == -1 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(%err, "snell tcp_fast_open could not be enabled");
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "cygwin",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "hurd",
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
)))]
fn try_enable_tcp_fast_open(_socket: &TcpSocket) {
    tracing::warn!("snell tcp_fast_open is unsupported on this platform");
}

pub(crate) async fn drain_connection_tasks<T: 'static>(
    mut tasks: JoinSet<T>,
    drain_timeout: Duration,
) {
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            log_connection_task_result(Some(result));
        }
    };

    if timeout(drain_timeout, drain).await.is_ok() {
        return;
    }

    let remaining = tasks.len();
    tracing::warn!(
        remaining,
        ?drain_timeout,
        "force closing active connections after shutdown timeout"
    );
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(_) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => tracing::debug!(%err, "snell connection task ended unexpectedly"),
        }
    }
}

pub(crate) fn log_connection_task_result<T>(
    result: Option<std::result::Result<T, tokio::task::JoinError>>,
) {
    if let Some(Err(err)) = result {
        tracing::debug!(%err, "snell connection task ended unexpectedly");
    }
}

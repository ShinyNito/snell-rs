//! Platform socket options and accept-error backoff.
//!
//! Keepalive uses socket2. TCP Fast Open and the tcp-brutal parameters go
//! through [`sockopt`], the only kernel FFI. Each OS module exports the same
//! functions, re-exported here; other platforms report them unsupported.

mod accept;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod sockopt;
mod udp;
#[cfg(all(test, windows))]
mod windows;

use std::io;
use std::time::Duration;

use snell_protocol::{TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

pub(crate) use accept::AcceptLoop;
#[cfg(target_os = "linux")]
pub(crate) use linux::{apply_tcp_brutal, set_tcp_fastopen_connect, set_tcp_fastopen_listener};
#[cfg(all(test, target_os = "linux"))]
pub(crate) use linux::{read_tcp_fastopen_connect, read_tcp_fastopen_listener};
#[cfg(all(test, target_os = "macos"))]
pub(crate) use macos::{read_tcp_fastopen_connect, read_tcp_fastopen_listener};
#[cfg(target_os = "macos")]
pub(crate) use macos::{set_tcp_fastopen_connect, set_tcp_fastopen_listener};
pub(crate) use udp::send_udp_parts;
#[cfg(all(test, windows))]
pub(crate) use windows::read_keepalive;

/// Validated tcp-brutal request. Off unless config sets this.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBrutal {
    pub send_mbps: u32,
    pub cwnd_gain: u32,
}

impl TcpBrutal {
    /// Send rate in bytes per second (`send_mbps` is SI megabits).
    pub fn rate_bytes_per_sec(self) -> u64 {
        u64::from(self.send_mbps) * 1_000_000 / 8
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("{0}")]
    Unsupported(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Keepalive {
    pub enabled: bool,
    pub idle: Duration,
    pub interval: Duration,
}

pub(crate) fn prepare_session_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    apply_keepalive(stream)
}

pub(crate) fn apply_keepalive(stream: &TcpStream) -> io::Result<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS))
        .with_interval(Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS));
    let sock = SockRef::from(stream);
    sock.set_tcp_keepalive(&keepalive)
}

#[cfg(all(test, unix))]
pub(crate) fn read_keepalive(stream: &TcpStream) -> Result<Keepalive, PlatformError> {
    let sock = SockRef::from(stream);
    Ok(Keepalive {
        enabled: sock.keepalive()?,
        idle: sock.tcp_keepalive_time()?,
        interval: sock.tcp_keepalive_interval()?,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn set_tcp_fastopen_listener(_: &tokio::net::TcpSocket) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported("tcp fast open"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use set_tcp_fastopen_listener as set_tcp_fastopen_connect;

#[cfg(all(test, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn read_tcp_fastopen_listener(_: &tokio::net::TcpSocket) -> Result<i32, PlatformError> {
    Err(PlatformError::Unsupported("tcp fast open"))
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) use read_tcp_fastopen_listener as read_tcp_fastopen_connect;

#[cfg(not(target_os = "linux"))]
pub(crate) fn apply_tcp_brutal(_: &TcpStream, _: TcpBrutal) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported("tcp_brutal is Linux-only"))
}

#[cfg(test)]
mod tests;

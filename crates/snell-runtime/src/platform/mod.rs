//! Platform socket options and accept-error backoff.
//!
//! Keepalive uses socket2. Unix TFO uses rustix AsFd-style sockopts. The only
//! remaining kernel FFI is Linux tcp-brutal `TCP_BRUTAL_PARAMS`.

mod accept;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod tfo;
#[cfg(windows)]
mod windows;

use std::io;
use std::time::Duration;

use snell_protocol::{TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream};

pub(crate) use accept::AcceptLoop;

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

/// TCP ECN is the kernel/stack default. Linux/macOS/Windows have no portable
/// per-socket TCP_ECN enable; this phase does not set `IP_TOS`.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcnPolicy {
    KernelDefault,
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

#[cfg(test)]
pub(crate) fn read_keepalive(stream: &TcpStream) -> Result<Keepalive, PlatformError> {
    #[cfg(unix)]
    {
        let sock = SockRef::from(stream);
        Ok(Keepalive {
            enabled: sock.keepalive()?,
            idle: sock.tcp_keepalive_time()?,
            interval: sock.tcp_keepalive_interval()?,
        })
    }
    #[cfg(windows)]
    {
        windows::read_keepalive(stream)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = stream;
        Err(PlatformError::Unsupported("tcp keepalive"))
    }
}

pub(crate) fn set_tcp_fastopen_listener(socket: &TcpSocket) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::set_tcp_fastopen_listener(socket)
    }
    #[cfg(target_os = "macos")]
    {
        macos::set_tcp_fastopen_listener(socket)
    }
    #[cfg(windows)]
    {
        windows::set_tcp_fastopen_listener(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = socket;
        Err(PlatformError::Unsupported("tcp fast open"))
    }
}

pub(crate) fn set_tcp_fastopen_connect(socket: &TcpSocket) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::set_tcp_fastopen_connect(socket)
    }
    #[cfg(target_os = "macos")]
    {
        macos::set_tcp_fastopen_connect(socket)
    }
    #[cfg(windows)]
    {
        windows::set_tcp_fastopen_connect(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = socket;
        Err(PlatformError::Unsupported("tcp fast open"))
    }
}

#[cfg(test)]
pub(crate) fn read_tcp_fastopen_connect(socket: &TcpSocket) -> Result<i32, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::read_tcp_fastopen_connect(socket)
    }
    #[cfg(target_os = "macos")]
    {
        macos::read_tcp_fastopen_listener(socket)
    }
    #[cfg(windows)]
    {
        windows::read_tcp_fastopen_listener(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = socket;
        Err(PlatformError::Unsupported("tcp fast open"))
    }
}

#[cfg(test)]
pub(crate) fn read_tcp_fastopen_listener(socket: &TcpSocket) -> Result<i32, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::read_tcp_fastopen_listener(socket)
    }
    #[cfg(target_os = "macos")]
    {
        macos::read_tcp_fastopen_listener(socket)
    }
    #[cfg(windows)]
    {
        windows::read_tcp_fastopen_listener(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = socket;
        Err(PlatformError::Unsupported("tcp fast open"))
    }
}

pub(crate) fn require_tcp_brutal(params: TcpBrutal) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::require_tcp_brutal(params)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err(PlatformError::Unsupported("tcp_brutal is Linux-only"))
    }
}

pub(crate) fn apply_tcp_brutal(stream: &TcpStream, params: TcpBrutal) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::apply_tcp_brutal(stream, params)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, params);
        Err(PlatformError::Unsupported("tcp_brutal is Linux-only"))
    }
}

#[cfg(test)]
pub(crate) fn tcp_ecn_policy() -> EcnPolicy {
    EcnPolicy::KernelDefault
}

#[cfg(test)]
mod tests;

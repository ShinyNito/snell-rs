//! Tokio runtime for Snell TCP and UDP sessions.
//!
//! Owns sockets, tasks, timeouts, reuse, auto-detect, replay, outbound,
//! bounded KDF, the SOCKS5 UDP dispatcher, and platform socket options.
//! The TCP hot path uses borrowed split, `try_join!`, and one vectored write
//! per batch of records in a [`snell_protocol::Buffer`]: no `mpsc`, no
//! per-record `Vec`, no unconditional `flush`. UDP associations may use a
//! bounded `mpsc` per association.

#![deny(unsafe_code)]

mod auto;
mod buffer;
mod bufio;
mod client;
mod codec;
mod dns;
mod error;
mod kdf;
mod outbound;
mod packet;
mod platform;
mod pool;
mod replay;
mod server;
mod session;
mod socks;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use snell_protocol::TCP_CONNECT_TIMEOUT_SECS;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;

pub use buffer::BufferPool;
pub use client::{ClientConfig, run_client, serve_client};
pub use error::SessionError;
pub use outbound::Outbound;
pub use platform::{PlatformError, TcpBrutal};
pub use pool::ReusePool;
pub use server::{ServerConfig, run_server, serve_server};
pub use snell_protocol::{ProtocolFlavor, ProtocolSelection};
pub use udp::{UdpLimits, UdpMetrics, UdpOptions};

fn new_tcp_socket(addr: SocketAddr) -> io::Result<TcpSocket> {
    if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
}

/// Fast open is best-effort: only real I/O errors fail the socket.
fn allow_unsupported(result: Result<(), PlatformError>) -> io::Result<()> {
    match result {
        Ok(()) | Err(PlatformError::Unsupported(_)) => Ok(()),
        Err(PlatformError::Io(error)) => Err(error),
    }
}

pub(crate) fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = new_tcp_socket(addr)?;
    socket.set_reuseaddr(true)?;
    socket.set_nodelay(true)?;
    socket.bind(addr)?;
    allow_unsupported(platform::set_tcp_fastopen_listener(&socket))?;
    socket.listen(1024)
}

pub(crate) async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream, SessionError> {
    let socket = new_tcp_socket(addr)?;
    socket.set_nodelay(true)?;
    allow_unsupported(platform::set_tcp_fastopen_connect(&socket))?;
    let stream = timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        socket.connect(addr),
    )
    .await
    .map_err(|_| SessionError::ConnectTimeout)??;
    platform::apply_keepalive(&stream)?;
    Ok(stream)
}

#[cfg(test)]
mod tests;

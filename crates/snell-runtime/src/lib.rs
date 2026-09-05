//! Tokio runtime for Snell TCP and UDP sessions.
//!
//! Owns sockets, tasks, timeouts, reuse, auto-detect, replay, outbound,
//! bounded KDF, the SOCKS5 UDP dispatcher, and platform socket options.
//! The TCP hot path uses borrowed split, `try_join!`, and a single
//! `write(pending())` of [`EncodeBuffer`] — no `mpsc`, no per-record `Vec`,
//! no unconditional `flush`. UDP associations may use a bounded `mpsc` per
//! association.

#![deny(unsafe_code)]

mod admission;
mod auto;
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

pub use admission::TcpLimits;
pub use client::{ClientConfig, run_client, serve_client};
pub use error::SessionError;
pub use outbound::Outbound;
pub use platform::{PlatformError, TcpBrutal};
pub use pool::ReusePool;
pub use server::{ServerConfig, run_server, serve_server};
pub use snell_protocol::{ProtocolFlavor, ProtocolSelection};
pub use udp::{UdpLimits, UdpMetrics, UdpOptions};

pub(crate) fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_nodelay(true)?;
    socket.bind(addr)?;
    match platform::set_tcp_fastopen_listener(&socket) {
        Ok(()) | Err(PlatformError::Unsupported(_)) => {}
        Err(PlatformError::Io(error)) => return Err(error),
    }
    socket.listen(1024)
}

pub(crate) async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream, SessionError> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_nodelay(true)?;
    match platform::set_tcp_fastopen_connect(&socket) {
        Ok(()) | Err(PlatformError::Unsupported(_)) => {}
        Err(PlatformError::Io(error)) => return Err(error.into()),
    }
    let stream = match timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        socket.connect(addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Err(SessionError::ConnectTimeout),
    };
    platform::apply_keepalive(&stream)?;
    Ok(stream)
}

#[cfg(test)]
mod tests;

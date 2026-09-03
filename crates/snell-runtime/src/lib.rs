//! Tokio runtime for Snell TCP and UDP sessions.
//!
//! Owns sockets, tasks, timeouts, reuse, auto-detect, replay, outbound,
//! bounded KDF, and the SOCKS5 UDP dispatcher. The TCP hot path uses borrowed
//! split, `try_join!`, and a single `write(pending())` of [`EncodeBuffer`] —
//! no `mpsc`, no per-record `Vec`, no unconditional `flush`. UDP associations
//! may use a bounded `mpsc` per association.

#![deny(unsafe_code)]

mod auto;
mod bufio;
mod client;
mod codec;
mod dns;
mod error;
mod kdf;
mod outbound;
mod packet;
mod pool;
mod replay;
mod server;
mod session;
mod socks;
mod udp;

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpSocket, TcpStream};

pub use client::{ClientConfig, run_client, serve_client};
pub use error::{DirectionEnd, SessionError};
pub use outbound::Outbound;
pub use pool::ReusePool;
pub use server::{ServerConfig, run_server, serve_server};
pub use snell_protocol as protocol;
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
    socket.listen(1024)
}

pub(crate) fn set_nodelay(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)
}

#[cfg(test)]
mod tests;

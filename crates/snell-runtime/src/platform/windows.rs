use rustix::net::sockopt;
use socket2::SockRef;
use tokio::net::TcpStream;

use super::{Keepalive, PlatformError};

pub(crate) fn read_keepalive(stream: &TcpStream) -> Result<Keepalive, PlatformError> {
    // socket2 0.6 does not expose tcp_keepalive_time/interval on Windows.
    // rustix 0.38 does (TCP_KEEPIDLE / TCP_KEEPINTVL).
    Ok(Keepalive {
        enabled: SockRef::from(stream).keepalive()?,
        idle: sockopt::get_tcp_keepidle(stream).map_err(std::io::Error::from)?,
        interval: sockopt::get_tcp_keepintvl(stream).map_err(std::io::Error::from)?,
    })
}

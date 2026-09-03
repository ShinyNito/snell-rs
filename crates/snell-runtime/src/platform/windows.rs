use tokio::net::TcpSocket;

use super::PlatformError;

pub(super) fn set_tcp_fastopen_listener(_socket: &TcpSocket) -> Result<(), PlatformError> {
    // rustix 0.38 and socket2 0.6 have no Windows TCP_FASTOPEN sockopt.
    Err(PlatformError::Unsupported("tcp fast open"))
}

pub(super) fn set_tcp_fastopen_connect(socket: &TcpSocket) -> Result<(), PlatformError> {
    set_tcp_fastopen_listener(socket)
}

#[cfg(test)]
pub(super) fn read_tcp_fastopen_listener(_socket: &TcpSocket) -> Result<i32, PlatformError> {
    Err(PlatformError::Unsupported("tcp fast open"))
}

#[cfg(test)]
pub(super) fn read_keepalive(
    stream: &tokio::net::TcpStream,
) -> Result<super::Keepalive, PlatformError> {
    use rustix::net::sockopt;
    use socket2::SockRef;

    // socket2 0.6 does not expose tcp_keepalive_time/interval on Windows.
    // rustix 0.38 does (TCP_KEEPIDLE / TCP_KEEPINTVL).
    Ok(super::Keepalive {
        enabled: SockRef::from(stream).keepalive()?,
        idle: sockopt::get_tcp_keepidle(stream)?,
        interval: sockopt::get_tcp_keepintvl(stream)?,
    })
}

use libc::TCP_FASTOPEN;
use rustix::io::Errno;
use tokio::net::TcpSocket;

use super::PlatformError;
use super::sockopt::set_tcp_int;

/// macOS uses one option for both sides of a connection.
pub(crate) fn set_tcp_fastopen_listener(socket: &TcpSocket) -> Result<(), PlatformError> {
    set_tcp_int(socket, TCP_FASTOPEN, 1).map_err(tfo_error)
}

pub(crate) use set_tcp_fastopen_listener as set_tcp_fastopen_connect;

#[cfg(test)]
pub(crate) fn read_tcp_fastopen_listener(socket: &TcpSocket) -> Result<i32, PlatformError> {
    super::sockopt::get_tcp_int(socket, TCP_FASTOPEN).map_err(tfo_error)
}

#[cfg(test)]
pub(crate) use read_tcp_fastopen_listener as read_tcp_fastopen_connect;

fn tfo_error(error: Errno) -> PlatformError {
    match error {
        Errno::NOPROTOOPT | Errno::OPNOTSUPP | Errno::NOTSUP | Errno::INVAL => {
            PlatformError::Unsupported("tcp fast open")
        }
        _ => PlatformError::Io(error.into()),
    }
}

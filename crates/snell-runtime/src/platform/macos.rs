use rustix::io::Errno;
use tokio::net::TcpSocket;

use super::PlatformError;

pub(super) fn set_tcp_fastopen_listener(socket: &TcpSocket) -> Result<(), PlatformError> {
    super::tfo::set_tcp_fastopen(socket, 1).map_err(tfo_error)
}

pub(super) fn set_tcp_fastopen_connect(socket: &TcpSocket) -> Result<(), PlatformError> {
    set_tcp_fastopen_listener(socket)
}

#[cfg(test)]
pub(super) fn read_tcp_fastopen_listener(socket: &TcpSocket) -> Result<i32, PlatformError> {
    super::tfo::get_tcp_fastopen(socket).map_err(tfo_error)
}

fn tfo_error(error: Errno) -> PlatformError {
    match error {
        Errno::NOPROTOOPT | Errno::OPNOTSUPP | Errno::NOTSUP | Errno::INVAL => {
            PlatformError::Unsupported("tcp fast open")
        }
        _ => PlatformError::Io(error.into()),
    }
}

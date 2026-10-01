use rustix::io::Errno;
use rustix::net::sockopt;
use socket2::SockRef;
use tokio::net::{TcpSocket, TcpStream};

use super::{PlatformError, TcpBrutal};

const TCP_FASTOPEN_QUEUE: i32 = 256;
/// Private sockopt of the out-of-tree tcp-brutal module; not in `libc`.
const TCP_BRUTAL_PARAMS: i32 = 23301;
const BRUTAL_PARAMS_LEN: usize = 12;

pub(super) fn set_tcp_fastopen_listener(socket: &TcpSocket) -> Result<(), PlatformError> {
    super::tfo::set_tcp_fastopen(socket, TCP_FASTOPEN_QUEUE).map_err(tfo_error)
}

pub(super) fn set_tcp_fastopen_connect(socket: &TcpSocket) -> Result<(), PlatformError> {
    super::tfo::set_tcp_fastopen_connect(socket, true).map_err(tfo_error)
}

#[cfg(test)]
pub(super) fn read_tcp_fastopen_listener(socket: &TcpSocket) -> Result<i32, PlatformError> {
    super::tfo::get_tcp_fastopen(socket).map_err(tfo_error)
}

#[cfg(test)]
pub(super) fn read_tcp_fastopen_connect(socket: &TcpSocket) -> Result<i32, PlatformError> {
    super::tfo::get_tcp_fastopen_connect(socket).map_err(tfo_error)
}

fn tfo_error(error: Errno) -> PlatformError {
    match error {
        Errno::NOPROTOOPT | Errno::OPNOTSUPP | Errno::INVAL => {
            PlatformError::Unsupported("tcp fast open")
        }
        _ => PlatformError::Io(error.into()),
    }
}

pub(super) fn apply_tcp_brutal(stream: &TcpStream, params: TcpBrutal) -> Result<(), PlatformError> {
    let sock = SockRef::from(stream);
    apply_brutal(&sock, params)
}

fn apply_brutal(sock: &socket2::Socket, params: TcpBrutal) -> Result<(), PlatformError> {
    sockopt::set_tcp_congestion(sock, "brutal").map_err(brutal_error)?;
    set_brutal_params(sock, params).map_err(brutal_error)
}

fn brutal_error(error: Errno) -> PlatformError {
    match error {
        Errno::NOPROTOOPT | Errno::OPNOTSUPP | Errno::NOENT | Errno::INVAL => {
            PlatformError::Unsupported("tcp_brutal is not available")
        }
        _ => PlatformError::Io(error.into()),
    }
}

fn set_brutal_params(sock: &socket2::Socket, params: TcpBrutal) -> Result<(), Errno> {
    super::tfo::set_tcp_opt(sock, TCP_BRUTAL_PARAMS, &brutal_params(params))
}

/// The tcp-brutal module ABI at `TCP_BRUTAL_PARAMS`: packed native-endian
/// `u64` rate in bytes per second, then `u32` cwnd_gain (`QI`).
fn brutal_params(params: TcpBrutal) -> [u8; BRUTAL_PARAMS_LEN] {
    let mut bytes = [0u8; BRUTAL_PARAMS_LEN];
    let (rate, gain) = bytes.split_at_mut(8);
    rate.copy_from_slice(&params.rate_bytes_per_sec().to_ne_bytes());
    gain.copy_from_slice(&params.cwnd_gain.to_ne_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brutal_params_are_12_byte_qi() {
        let bytes = brutal_params(TcpBrutal {
            send_mbps: 16,
            cwnd_gain: 15,
        });
        assert_eq!(&bytes[..8], &2_000_000u64.to_ne_bytes());
        assert_eq!(&bytes[8..], &15u32.to_ne_bytes());
    }
}

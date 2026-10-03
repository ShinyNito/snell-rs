use libc::{TCP_FASTOPEN, TCP_FASTOPEN_CONNECT};
use rustix::io::Errno;
use rustix::net::sockopt;
use tokio::net::{TcpSocket, TcpStream};

use super::sockopt::{set_tcp_int, set_tcp_opt};
use super::{PlatformError, TcpBrutal};

const TCP_FASTOPEN_QUEUE: i32 = 256;
/// Private sockopt of the out-of-tree tcp-brutal module; not in `libc`.
const TCP_BRUTAL_PARAMS: i32 = 23301;
const BRUTAL_PARAMS_LEN: usize = 12;

pub(crate) fn set_tcp_fastopen_listener(socket: &TcpSocket) -> Result<(), PlatformError> {
    set_tcp_int(socket, TCP_FASTOPEN, TCP_FASTOPEN_QUEUE).map_err(tfo_error)
}

pub(crate) fn set_tcp_fastopen_connect(socket: &TcpSocket) -> Result<(), PlatformError> {
    set_tcp_int(socket, TCP_FASTOPEN_CONNECT, 1).map_err(tfo_error)
}

#[cfg(test)]
pub(crate) fn read_tcp_fastopen_listener(socket: &TcpSocket) -> Result<i32, PlatformError> {
    super::sockopt::get_tcp_int(socket, TCP_FASTOPEN).map_err(tfo_error)
}

#[cfg(test)]
pub(crate) fn read_tcp_fastopen_connect(socket: &TcpSocket) -> Result<i32, PlatformError> {
    super::sockopt::get_tcp_int(socket, TCP_FASTOPEN_CONNECT).map_err(tfo_error)
}

fn tfo_error(error: Errno) -> PlatformError {
    match error {
        Errno::NOPROTOOPT | Errno::OPNOTSUPP | Errno::INVAL => {
            PlatformError::Unsupported("tcp fast open")
        }
        _ => PlatformError::Io(error.into()),
    }
}

pub(crate) fn apply_tcp_brutal(stream: &TcpStream, params: TcpBrutal) -> Result<(), PlatformError> {
    sockopt::set_tcp_congestion(stream, "brutal").map_err(brutal_error)?;
    set_tcp_opt(stream, TCP_BRUTAL_PARAMS, &brutal_params(params)).map_err(brutal_error)
}

fn brutal_error(error: Errno) -> PlatformError {
    match error {
        Errno::NOPROTOOPT | Errno::OPNOTSUPP | Errno::NOENT | Errno::INVAL => {
            PlatformError::Unsupported("tcp_brutal is not available")
        }
        _ => PlatformError::Io(error.into()),
    }
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

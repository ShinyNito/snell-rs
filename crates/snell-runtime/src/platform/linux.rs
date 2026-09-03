use rustix::fd::{AsFd, AsRawFd};
use rustix::io::Errno;
use rustix::net::sockopt;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream};

use super::{PlatformError, TcpBrutal};

const TCP_FASTOPEN_QUEUE: i32 = 256;
const TCP_BRUTAL_PARAMS: i32 = 23301;
const BRUTAL_PARAMS_LEN: usize = 12;
const IPPROTO_TCP: i32 = 6;

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

pub(super) fn require_tcp_brutal(params: TcpBrutal) -> Result<(), PlatformError> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    apply_brutal(&socket, params)?;
    let name = sockopt::get_tcp_congestion(&socket).map_err(brutal_error)?;
    if name.trim_end_matches('\0') != "brutal" {
        return Err(PlatformError::Unsupported(
            "tcp_brutal requested but congestion control is not brutal",
        ));
    }
    Ok(())
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

/// Sets the tcp-brutal private sockopt `TCP_BRUTAL_PARAMS = 23301`.
///
/// Non-standard kernel module ABI (packed `u64` rate + `u32` cwnd_gain).
/// Not in rustix. Isolated from keepalive and rustix `TCP_CONGESTION`.
#[allow(unsafe_code)]
fn set_brutal_params<Fd: AsFd>(fd: Fd, params: TcpBrutal) -> Result<(), Errno> {
    let mut bytes = [0u8; BRUTAL_PARAMS_LEN];
    bytes[..8].copy_from_slice(&params.rate_bytes_per_sec().to_ne_bytes());
    bytes[8..].copy_from_slice(&params.cwnd_gain.to_ne_bytes());
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: `raw` is a live TCP socket. The brutal module reads exactly 12
    // bytes (`QI`) at `TCP_BRUTAL_PARAMS`. We do not close `raw`.
    let ret = unsafe {
        libc::setsockopt(
            raw,
            IPPROTO_TCP,
            TCP_BRUTAL_PARAMS,
            bytes.as_ptr().cast(),
            BRUTAL_PARAMS_LEN as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::IO))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brutal_params_are_12_byte_qi() {
        let params = TcpBrutal {
            send_mbps: 16,
            cwnd_gain: 15,
        };
        let mut bytes = [0u8; BRUTAL_PARAMS_LEN];
        bytes[..8].copy_from_slice(&params.rate_bytes_per_sec().to_ne_bytes());
        bytes[8..].copy_from_slice(&params.cwnd_gain.to_ne_bytes());
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..8], &(2_000_000u64).to_ne_bytes());
        assert_eq!(&bytes[8..], &15u32.to_ne_bytes());
    }
}

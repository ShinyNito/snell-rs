use std::{io, time::Duration};

use compio::net::TcpStream;

#[cfg(any(unix, windows))]
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(5 * 60);
#[cfg(any(unix, windows))]
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(75);

#[cfg(unix)]
pub(crate) fn apply_tcp_keepalive(stream: &TcpStream) -> io::Result<()> {
    rustix::net::sockopt::set_socket_keepalive(stream, true)?;
    set_tcp_keepalive_idle(stream)?;
    set_tcp_keepalive_interval(stream)
}

#[cfg(windows)]
pub(crate) fn apply_tcp_keepalive(stream: &TcpStream) -> io::Result<()> {
    use std::{mem::size_of, os::windows::io::AsRawSocket, ptr::null_mut};

    let mut values = TcpKeepalive {
        onoff: 1,
        keepalivetime: duration_millis_u32(TCP_KEEPALIVE_IDLE),
        keepaliveinterval: duration_millis_u32(TCP_KEEPALIVE_INTERVAL),
    };
    let mut bytes_returned = 0;
    let result = unsafe {
        WSAIoctl(
            stream.as_raw_socket(),
            SIO_KEEPALIVE_VALS,
            (&raw mut values).cast(),
            u32::try_from(size_of::<TcpKeepalive>()).expect("tcp_keepalive size fits DWORD"),
            null_mut(),
            0,
            &mut bytes_returned,
            null_mut(),
            null_mut(),
        )
    };
    if result == SOCKET_ERROR {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn apply_tcp_keepalive(_stream: &TcpStream) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
const SIO_KEEPALIVE_VALS: u32 = 0x9800_0004;
#[cfg(windows)]
const SOCKET_ERROR: i32 = -1;

#[cfg(windows)]
#[repr(C)]
struct TcpKeepalive {
    onoff: u32,
    keepalivetime: u32,
    keepaliveinterval: u32,
}

#[cfg(windows)]
fn duration_millis_u32(duration: Duration) -> u32 {
    duration
        .as_millis()
        .try_into()
        .expect("tcp keepalive duration fits DWORD")
}

#[cfg(windows)]
#[link(name = "Ws2_32")]
unsafe extern "system" {
    #[allow(non_snake_case)]
    fn WSAIoctl(
        s: std::os::windows::io::RawSocket,
        dwIoControlCode: u32,
        lpvInBuffer: *mut std::ffi::c_void,
        cbInBuffer: u32,
        lpvOutBuffer: *mut std::ffi::c_void,
        cbOutBuffer: u32,
        lpcbBytesReturned: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
        lpCompletionRoutine: *mut std::ffi::c_void,
    ) -> i32;

    #[allow(non_snake_case)]
    fn WSAGetLastError() -> i32;
}

#[cfg(all(
    unix,
    not(any(target_os = "haiku", target_os = "nto", target_os = "openbsd"))
))]
fn set_tcp_keepalive_idle(stream: &TcpStream) -> io::Result<()> {
    Ok(rustix::net::sockopt::set_tcp_keepidle(
        stream,
        TCP_KEEPALIVE_IDLE,
    )?)
}

#[cfg(all(
    unix,
    any(target_os = "haiku", target_os = "nto", target_os = "openbsd")
))]
fn set_tcp_keepalive_idle(_stream: &TcpStream) -> io::Result<()> {
    Ok(())
}

#[cfg(all(
    unix,
    not(any(
        target_os = "haiku",
        target_os = "nto",
        target_os = "openbsd",
        target_os = "redox"
    ))
))]
fn set_tcp_keepalive_interval(stream: &TcpStream) -> io::Result<()> {
    Ok(rustix::net::sockopt::set_tcp_keepintvl(
        stream,
        TCP_KEEPALIVE_INTERVAL,
    )?)
}

#[cfg(all(
    unix,
    any(
        target_os = "haiku",
        target_os = "nto",
        target_os = "openbsd",
        target_os = "redox"
    )
))]
fn set_tcp_keepalive_interval(_stream: &TcpStream) -> io::Result<()> {
    Ok(())
}

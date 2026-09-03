//! TCP Fast Open sockopts in rustix's AsFd style.
//!
//! rustix 0.38 has no `set_tcp_fastopen` / `set_tcp_fastopen_connect`. These
//! typed i32 helpers are the real sockopt API on `AsFd`.

use std::mem;
#[cfg(test)]
use std::mem::MaybeUninit;

use rustix::fd::{AsFd, AsRawFd};
use rustix::io::Errno;

const IPPROTO_TCP: i32 = 6;

#[cfg(target_os = "linux")]
const TCP_FASTOPEN: i32 = 23;
#[cfg(target_os = "linux")]
const TCP_FASTOPEN_CONNECT: i32 = 30;
#[cfg(target_os = "macos")]
const TCP_FASTOPEN: i32 = 0x105;

pub(super) fn set_tcp_fastopen<Fd: AsFd>(fd: Fd, value: i32) -> Result<(), Errno> {
    set_tcp_i32(fd, TCP_FASTOPEN, value)
}

#[cfg(test)]
pub(super) fn get_tcp_fastopen<Fd: AsFd>(fd: Fd) -> Result<i32, Errno> {
    get_tcp_i32(fd, TCP_FASTOPEN)
}

#[cfg(target_os = "linux")]
pub(super) fn set_tcp_fastopen_connect<Fd: AsFd>(fd: Fd, value: bool) -> Result<(), Errno> {
    set_tcp_i32(fd, TCP_FASTOPEN_CONNECT, i32::from(value))
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn get_tcp_fastopen_connect<Fd: AsFd>(fd: Fd) -> Result<i32, Errno> {
    get_tcp_i32(fd, TCP_FASTOPEN_CONNECT)
}

#[allow(unsafe_code)]
fn set_tcp_i32<Fd: AsFd>(fd: Fd, optname: i32, value: i32) -> Result<(), Errno> {
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: `raw` is a live TCP socket borrowed via `AsFd`. `TCP_FASTOPEN`
    // and `TCP_FASTOPEN_CONNECT` take a `c_int`; we pass that type and size.
    let ret = unsafe {
        libc::setsockopt(
            raw,
            IPPROTO_TCP,
            optname,
            (&value as *const i32).cast(),
            mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret == 0 { Ok(()) } else { Err(last_errno()) }
}

#[cfg(test)]
#[allow(unsafe_code)]
fn get_tcp_i32<Fd: AsFd>(fd: Fd, optname: i32) -> Result<i32, Errno> {
    let raw = fd.as_fd().as_raw_fd();
    let mut value = MaybeUninit::<i32>::zeroed();
    let mut len = mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: `raw` is a live TCP socket. `value` is zeroed; the kernel writes
    // an i32 (or a prefix) for these options.
    let ret = unsafe {
        libc::getsockopt(
            raw,
            IPPROTO_TCP,
            optname,
            value.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(last_errno());
    }
    // SAFETY: `value` was zeroed and getsockopt wrote the option prefix.
    Ok(unsafe { value.assume_init() })
}

fn last_errno() -> Errno {
    Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::IO)
}

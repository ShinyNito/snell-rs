//! `IPPROTO_TCP` sockopts that neither rustix 0.38 nor socket2 0.6 expose:
//! TCP Fast Open, and (on Linux) the tcp-brutal module's parameters. Option
//! numbers come from `libc`; every write goes through [`set_tcp_opt`].

#[cfg(test)]
use std::mem::MaybeUninit;

#[cfg(target_os = "linux")]
use libc::TCP_FASTOPEN_CONNECT;
use libc::{IPPROTO_TCP, TCP_FASTOPEN};
use rustix::fd::{AsFd, AsRawFd};
use rustix::io::Errno;

pub(super) fn set_tcp_fastopen<Fd: AsFd>(fd: Fd, value: i32) -> Result<(), Errno> {
    set_tcp_opt(fd, TCP_FASTOPEN, &value.to_ne_bytes())
}

#[cfg(test)]
pub(super) fn get_tcp_fastopen<Fd: AsFd>(fd: Fd) -> Result<i32, Errno> {
    get_tcp_i32(fd, TCP_FASTOPEN)
}

#[cfg(target_os = "linux")]
pub(super) fn set_tcp_fastopen_connect<Fd: AsFd>(fd: Fd, value: bool) -> Result<(), Errno> {
    set_tcp_opt(fd, TCP_FASTOPEN_CONNECT, &i32::from(value).to_ne_bytes())
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn get_tcp_fastopen_connect<Fd: AsFd>(fd: Fd) -> Result<i32, Errno> {
    get_tcp_i32(fd, TCP_FASTOPEN_CONNECT)
}

/// Set `IPPROTO_TCP` option `optname` to the raw bytes of its value.
#[allow(unsafe_code)]
pub(super) fn set_tcp_opt<Fd: AsFd>(fd: Fd, optname: i32, value: &[u8]) -> Result<(), Errno> {
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: `raw` is a live TCP socket borrowed via `AsFd`, and the kernel
    // reads at most `value.len()` bytes from a pointer valid for that length.
    // Callers pass each option's native layout: a `c_int`, or tcp-brutal's
    // packed 12-byte parameters.
    let ret = unsafe {
        libc::setsockopt(
            raw,
            IPPROTO_TCP,
            optname,
            value.as_ptr().cast(),
            value.len() as libc::socklen_t,
        )
    };
    if ret == 0 { Ok(()) } else { Err(last_errno()) }
}

#[cfg(test)]
#[allow(unsafe_code)]
fn get_tcp_i32<Fd: AsFd>(fd: Fd, optname: i32) -> Result<i32, Errno> {
    let raw = fd.as_fd().as_raw_fd();
    let mut value = MaybeUninit::<i32>::zeroed();
    let mut len = size_of::<i32>() as libc::socklen_t;
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

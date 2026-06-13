use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::{TcpListener, TcpStream};

use crate::config::TcpBrutalConfig;
use crate::error::Result;

pub(crate) fn apply_tcp_brutal(stream: &TcpStream, config: Option<TcpBrutalConfig>) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    apply_tcp_brutal_enabled(stream, config).map_err(Into::into)
}

pub(crate) async fn validate_tcp_brutal_available(config: Option<TcpBrutalConfig>) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;
    let (_client, (server, _peer)) = tokio::try_join!(TcpStream::connect(addr), listener.accept())?;
    apply_tcp_brutal(&server, Some(config))
}

#[cfg(target_os = "linux")]
fn apply_tcp_brutal_enabled(stream: &TcpStream, config: TcpBrutalConfig) -> io::Result<()> {
    use std::mem::size_of_val;
    use std::os::fd::AsRawFd;
    use std::ptr;

    const TCP_BRUTAL_PARAMS: libc::c_int = 23301;

    #[repr(C, packed)]
    struct BrutalParams {
        rate: u64,
        cwnd_gain: u32,
    }

    let fd = stream.as_raw_fd();
    let congestion = b"brutal";
    set_tcp_sockopt(
        fd,
        libc::TCP_CONGESTION,
        congestion.as_ptr().cast(),
        congestion.len(),
    )?;

    let params = BrutalParams {
        rate: config.rate_bytes_per_sec,
        cwnd_gain: config.cwnd_gain,
    };
    set_tcp_sockopt(
        fd,
        TCP_BRUTAL_PARAMS,
        ptr::addr_of!(params).cast(),
        size_of_val(&params),
    )
}

#[cfg(target_os = "linux")]
fn set_tcp_sockopt(
    fd: libc::c_int,
    opt: libc::c_int,
    value: *const libc::c_void,
    len: usize,
) -> io::Result<()> {
    // SAFETY: `value` points to a live socket option buffer for the duration of
    // the call, and `len` is converted to the platform socklen_t.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            opt,
            value,
            len.try_into()
                .expect("tcp socket option length fits socklen_t"),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_tcp_brutal_enabled(_stream: &TcpStream, _config: TcpBrutalConfig) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tcp_brutal is only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::validate_tcp_brutal_available;

    #[tokio::test]
    async fn disabled_tcp_brutal_validation_is_noop() {
        validate_tcp_brutal_available(None).await.unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn enabled_tcp_brutal_validation_fails_on_non_linux() {
        let result = validate_tcp_brutal_available(Some(crate::config::TcpBrutalConfig {
            rate_bytes_per_sec: 1_000_000,
            cwnd_gain: 20,
        }))
        .await;

        assert!(result.is_err());
    }
}

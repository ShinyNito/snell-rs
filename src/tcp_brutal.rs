use std::io;

use compio::net::{TcpListener, TcpStream};

use crate::config::TcpBrutalConfig;

pub(crate) fn apply_tcp_brutal(
    stream: &TcpStream,
    config: Option<TcpBrutalConfig>,
) -> io::Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    apply_tcp_brutal_enabled(stream, config)
}

pub(crate) async fn validate_tcp_brutal_available(
    config: Option<TcpBrutalConfig>,
) -> io::Result<()> {
    let Some(config) = config else {
        return Ok(());
    };

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (client, accepted) =
        futures::future::try_join(TcpStream::connect(addr), listener.accept()).await?;
    let (server, _peer) = accepted;
    drop(client);
    apply_tcp_brutal(&server, Some(config))
}

#[cfg(target_os = "linux")]
fn apply_tcp_brutal_enabled(stream: &TcpStream, config: TcpBrutalConfig) -> io::Result<()> {
    use std::{
        ffi::{c_int, c_void},
        mem::size_of_val,
        os::fd::AsRawFd,
        ptr,
    };

    const IPPROTO_TCP: c_int = 6;
    const TCP_BRUTAL_PARAMS: c_int = 23301;

    #[repr(C, packed)]
    struct BrutalParams {
        rate: u64,
        cwnd_gain: u32,
    }

    unsafe extern "C" {
        fn setsockopt(
            socket: c_int,
            level: c_int,
            option_name: c_int,
            option_value: *const c_void,
            option_len: u32,
        ) -> c_int;
    }

    let params = BrutalParams {
        rate: config.rate_bytes_per_sec,
        cwnd_gain: config.cwnd_gain,
    };

    rustix::net::sockopt::set_tcp_congestion(stream, "brutal")?;
    // SAFETY: `params` lives for the whole call and the option length is the
    // exact size of the packed kernel parameter struct used by tcp-brutal.
    let rc = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            IPPROTO_TCP,
            TCP_BRUTAL_PARAMS,
            ptr::addr_of!(params).cast(),
            size_of_val(&params)
                .try_into()
                .expect("tcp-brutal option length fits socklen_t"),
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

    #[compio::test]
    async fn disabled_tcp_brutal_validation_is_noop() {
        validate_tcp_brutal_available(None).await.unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[compio::test]
    async fn enabled_tcp_brutal_validation_fails_on_non_linux() {
        let result = validate_tcp_brutal_available(Some(crate::config::TcpBrutalConfig {
            rate_bytes_per_sec: 1_000_000,
            cwnd_gain: 20,
        }))
        .await;

        assert!(result.is_err());
    }
}

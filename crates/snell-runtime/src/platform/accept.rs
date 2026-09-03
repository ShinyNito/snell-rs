use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

/// First backoff after EMFILE/ENFILE. Doubles up to [`ACCEPT_BACKOFF_MAX`].
pub(crate) const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(16);
/// Cap for accept-error backoff. Not a session-count semaphore.
pub(crate) const ACCEPT_BACKOFF_MAX: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcceptClass {
    Resource,
    Ignore,
    Fatal,
}

#[derive(Debug)]
pub(crate) enum OnAccept {
    Ready(TcpStream, SocketAddr),
    RetryAfter(Duration),
}

#[derive(Debug, Default)]
pub(crate) struct AcceptBackoff {
    consecutive: u32,
}

impl AcceptBackoff {
    pub(crate) fn new() -> Self {
        Self { consecutive: 0 }
    }

    pub(crate) fn reset(&mut self) {
        self.consecutive = 0;
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let shift = self.consecutive.min(8);
        self.consecutive = self.consecutive.saturating_add(1);
        let millis = ACCEPT_BACKOFF_MIN.as_millis() << shift;
        Duration::from_millis(u64::try_from(millis.min(ACCEPT_BACKOFF_MAX.as_millis())).unwrap())
    }
}

pub(crate) fn classify_accept_error(error: &io::Error) -> AcceptClass {
    if is_resource_limit(error) {
        return AcceptClass::Resource;
    }
    if is_ignorable_accept(error) {
        return AcceptClass::Ignore;
    }
    AcceptClass::Fatal
}

pub(crate) fn on_accept_result(
    result: io::Result<(TcpStream, SocketAddr)>,
    backoff: &mut AcceptBackoff,
) -> Result<OnAccept, io::Error> {
    match result {
        Ok((stream, addr)) => {
            backoff.reset();
            Ok(OnAccept::Ready(stream, addr))
        }
        Err(error) => match classify_accept_error(&error) {
            AcceptClass::Resource => Ok(OnAccept::RetryAfter(backoff.next_delay())),
            AcceptClass::Ignore => Ok(OnAccept::RetryAfter(Duration::ZERO)),
            AcceptClass::Fatal => Err(error),
        },
    }
}

pub(crate) async fn apply_accept_result(
    result: io::Result<(TcpStream, SocketAddr)>,
    backoff: &mut AcceptBackoff,
) -> Result<Option<(TcpStream, SocketAddr)>, io::Error> {
    match on_accept_result(result, backoff)? {
        OnAccept::Ready(stream, addr) => Ok(Some((stream, addr))),
        OnAccept::RetryAfter(delay) => {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Ok(None)
        }
    }
}

pub(crate) struct AcceptLoop<'a> {
    listener: &'a TcpListener,
    backoff: AcceptBackoff,
    #[cfg(test)]
    pub(crate) inject: std::collections::VecDeque<io::Error>,
}

impl<'a> AcceptLoop<'a> {
    pub(crate) fn new(listener: &'a TcpListener) -> Self {
        Self {
            listener,
            backoff: AcceptBackoff::new(),
            #[cfg(test)]
            inject: std::collections::VecDeque::new(),
        }
    }

    pub(crate) async fn next(&mut self) -> Result<(TcpStream, SocketAddr), io::Error> {
        loop {
            if let Some(pair) =
                apply_accept_result(self.accept_once().await, &mut self.backoff).await?
            {
                return Ok(pair);
            }
        }
    }

    async fn accept_once(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        #[cfg(test)]
        if let Some(error) = self.inject.pop_front() {
            return Err(error);
        }
        self.listener.accept().await
    }
}

#[cfg(test)]
pub(crate) fn emfile_error() -> io::Error {
    io::Error::from_raw_os_error(emfile_code())
}

#[cfg(test)]
pub(crate) fn enfile_error() -> io::Error {
    io::Error::from_raw_os_error(enfile_code())
}

fn is_resource_limit(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::OutOfMemory | io::ErrorKind::QuotaExceeded
    ) {
        return true;
    }
    match error.raw_os_error() {
        Some(code) => resource_codes().contains(&code),
        None => false,
    }
}

fn is_ignorable_accept(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::ConnectionAborted {
        return true;
    }
    error.raw_os_error() == Some(conn_aborted_code())
}

#[cfg(test)]
fn emfile_code() -> i32 {
    rustix::io::Errno::MFILE.raw_os_error()
}

#[cfg(test)]
fn enfile_code() -> i32 {
    #[cfg(unix)]
    {
        rustix::io::Errno::NFILE.raw_os_error()
    }
    #[cfg(windows)]
    {
        rustix::io::Errno::MFILE.raw_os_error()
    }
}

fn conn_aborted_code() -> i32 {
    rustix::io::Errno::CONNABORTED.raw_os_error()
}

#[cfg(unix)]
fn resource_codes() -> [i32; 4] {
    [
        rustix::io::Errno::MFILE.raw_os_error(),
        rustix::io::Errno::NFILE.raw_os_error(),
        rustix::io::Errno::NOBUFS.raw_os_error(),
        rustix::io::Errno::NOMEM.raw_os_error(),
    ]
}

#[cfg(windows)]
fn resource_codes() -> [i32; 3] {
    [
        rustix::io::Errno::MFILE.raw_os_error(),
        rustix::io::Errno::NOBUFS.raw_os_error(),
        rustix::io::Errno::NOMEM.raw_os_error(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emfile_and_enfile_are_resource_limits() {
        assert_eq!(
            classify_accept_error(&emfile_error()),
            AcceptClass::Resource
        );
        assert_eq!(
            classify_accept_error(&enfile_error()),
            AcceptClass::Resource
        );
    }

    #[test]
    fn connection_aborted_is_ignored() {
        let error = io::Error::from_raw_os_error(conn_aborted_code());
        assert_eq!(classify_accept_error(&error), AcceptClass::Ignore);
    }

    #[test]
    fn other_accept_errors_are_fatal() {
        let error = io::Error::other("listener broken");
        assert_eq!(classify_accept_error(&error), AcceptClass::Fatal);
        let mut backoff = AcceptBackoff::new();
        let err = on_accept_result(Err(error), &mut backoff).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn resource_backoff_is_bounded() {
        let mut backoff = AcceptBackoff::new();
        let mut last = Duration::ZERO;
        for _ in 0..16 {
            let OnAccept::RetryAfter(delay) =
                on_accept_result(Err(emfile_error()), &mut backoff).unwrap()
            else {
                panic!("EMFILE must retry");
            };
            assert!(delay >= ACCEPT_BACKOFF_MIN);
            assert!(delay <= ACCEPT_BACKOFF_MAX);
            last = delay;
        }
        assert_eq!(last, ACCEPT_BACKOFF_MAX);
    }
}

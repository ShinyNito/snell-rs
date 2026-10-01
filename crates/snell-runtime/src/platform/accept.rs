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

#[derive(Debug, Default)]
pub(crate) struct AcceptBackoff {
    consecutive: u32,
}

impl AcceptBackoff {
    pub(crate) fn reset(&mut self) {
        self.consecutive = 0;
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let shift = self.consecutive.min(8);
        self.consecutive = self.consecutive.saturating_add(1);
        ACCEPT_BACKOFF_MIN
            .saturating_mul(1 << shift)
            .min(ACCEPT_BACKOFF_MAX)
    }
}

pub(crate) fn classify_accept_error(error: &io::Error) -> AcceptClass {
    if is_resource_limit(error) {
        AcceptClass::Resource
    } else if is_ignorable_accept(error) {
        AcceptClass::Ignore
    } else {
        AcceptClass::Fatal
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
            backoff: AcceptBackoff::default(),
            #[cfg(test)]
            inject: std::collections::VecDeque::new(),
        }
    }

    /// Next connection. Descriptor exhaustion backs off instead of tearing
    /// the listener down; aborted handshakes are skipped.
    pub(crate) async fn next(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        loop {
            let error = match self.accept_once().await {
                Ok(accepted) => {
                    self.backoff.reset();
                    return Ok(accepted);
                }
                Err(error) => error,
            };
            match classify_accept_error(&error) {
                AcceptClass::Resource => {
                    let delay = self.backoff.next_delay();
                    if self.backoff.consecutive == 1 {
                        tracing::warn!(
                            delay_ms = delay.as_millis(),
                            "accept backing off (file descriptors exhausted)"
                        );
                    }
                    tokio::time::sleep(delay).await;
                }
                AcceptClass::Ignore => {}
                AcceptClass::Fatal => return Err(error),
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
    matches!(
        error.kind(),
        io::ErrorKind::OutOfMemory | io::ErrorKind::QuotaExceeded
    ) || error
        .raw_os_error()
        .is_some_and(|code| resource_codes().contains(&code))
}

fn is_ignorable_accept(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ConnectionAborted
        || error.raw_os_error() == Some(conn_aborted_code())
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
fn resource_codes() -> [i32; 2] {
    [
        rustix::io::Errno::MFILE.raw_os_error(),
        rustix::io::Errno::NOBUFS.raw_os_error(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_errors_are_classified() {
        for error in [emfile_error(), enfile_error()] {
            assert_eq!(classify_accept_error(&error), AcceptClass::Resource);
        }
        let aborted = io::Error::from_raw_os_error(conn_aborted_code());
        assert_eq!(classify_accept_error(&aborted), AcceptClass::Ignore);
        let broken = io::Error::other("listener broken");
        assert_eq!(classify_accept_error(&broken), AcceptClass::Fatal);
    }

    #[test]
    fn resource_backoff_doubles_to_the_cap_and_resets() {
        let mut backoff = AcceptBackoff::default();
        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_MIN);
        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_MIN * 2);
        let last = (0..16).map(|_| backoff.next_delay()).last().unwrap();
        assert_eq!(last, ACCEPT_BACKOFF_MAX);
        backoff.reset();
        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_MIN);
    }
}

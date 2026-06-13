use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::task::JoinSet;
use tokio::time::timeout;

pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const TCP_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_CONNECT_RACE_LIMIT: usize = 2;

pub(crate) async fn connect_tcp<A>(addr: A) -> std::io::Result<TcpStream>
where
    A: ToSocketAddrs,
{
    timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp connect timed out"))?
}

pub(crate) async fn connect_tcp_any(addrs: Vec<SocketAddr>) -> std::io::Result<TcpStream> {
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no allowed target address",
        ));
    }

    let mut addrs = addrs.into_iter();
    let mut tasks = JoinSet::new();
    for _ in 0..TCP_CONNECT_RACE_LIMIT {
        let Some(addr) = addrs.next() else {
            break;
        };
        tasks.spawn(connect_tcp(addr));
    }

    let mut last_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return Ok(stream);
            }
            Ok(Err(err)) => last_error = Some(err),
            Err(err) => {
                last_error = Some(std::io::Error::other(err));
            }
        }

        if let Some(addr) = addrs.next() {
            tasks.spawn(connect_tcp(addr));
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no allowed target address",
        )
    }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::connect_tcp_any;
    use crate::test_support::test_tcp_listener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connect_tcp_any_returns_first_successful_connection() {
        let unused = test_tcp_listener().await;
        let unused_addr = unused.local_addr().unwrap();
        drop(unused);

        let listener = test_tcp_listener().await;
        let addr = listener.local_addr().unwrap();

        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        };
        let client = async {
            let mut stream = connect_tcp_any(vec![unused_addr, addr]).await.unwrap();
            let mut out = [0; 4];
            stream.read_exact(&mut out).await.unwrap();
            assert_eq!(&out, b"pong");
        };

        let ((), ()) = tokio::join!(server, client);
    }

    #[tokio::test]
    async fn connect_tcp_any_rejects_empty_candidates() {
        let err = connect_tcp_any(Vec::new()).await.unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    }

    #[tokio::test]
    async fn connect_tcp_any_returns_connect_error_when_all_candidates_fail() {
        let unused = test_tcp_listener().await;
        let unused_addr = unused.local_addr().unwrap();
        drop(unused);

        let err = connect_tcp_any(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            unused_addr.port(),
        )])
        .await
        .unwrap_err();

        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
            ),
            "{err:?}"
        );
    }
}

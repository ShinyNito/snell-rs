use std::time::Duration;

use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;

pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn connect_tcp<A>(addr: A) -> std::io::Result<TcpStream>
where
    A: ToSocketAddrs,
{
    timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp connect timed out"))?
}

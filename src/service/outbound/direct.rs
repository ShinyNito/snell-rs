use std::net::{IpAddr, SocketAddr};

use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

use crate::service::runtime::net::{TCP_RESOLVE_TIMEOUT, connect_tcp, connect_tcp_any};

pub(crate) async fn open_direct_tcp(
    host: &str,
    port: u16,
    ipv6: bool,
) -> std::io::Result<TcpStream> {
    reject_disabled_ipv6_literal(host, ipv6)?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        let stream = connect_tcp(SocketAddr::new(ip, port)).await?;
        stream.set_nodelay(true)?;
        return Ok(stream);
    }

    let addrs = timeout(TCP_RESOLVE_TIMEOUT, lookup_host((host, port)))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp resolve timed out")
        })??;
    let addrs = addrs
        .filter(|addr| ipv6 || addr.is_ipv4())
        .collect::<Vec<_>>();
    let stream = connect_tcp_any(addrs).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

pub(crate) fn reject_disabled_ipv6_literal(host: &str, ipv6: bool) -> std::io::Result<()> {
    if !ipv6 && host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ipv6 target is disabled",
        ));
    }
    Ok(())
}

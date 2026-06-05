use std::net::{IpAddr, SocketAddr};

use tokio::net::{TcpStream, lookup_host};

use crate::service::runtime::net::connect_tcp;

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

    let addrs = lookup_host((host, port)).await?;
    let mut last_error = None;
    for addr in addrs.filter(|addr| ipv6 || addr.is_ipv4()) {
        match connect_tcp(addr).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no allowed target address",
        )
    }))
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

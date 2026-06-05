use tokio::net::TcpStream;

use crate::error::Result;
use crate::service::outbound::socks5::connect_tcp_via_socks5;

use super::direct::{open_direct_tcp, reject_disabled_ipv6_literal};
use super::{RelayOptions, UpstreamRelay, address_ref_from_host};

pub(crate) async fn open_tcp(host: &str, port: u16, options: RelayOptions) -> Result<TcpStream> {
    reject_disabled_ipv6_literal(host, options.ipv6)?;
    match options.upstream {
        UpstreamRelay::Direct => Ok(open_direct_tcp(host, port, options.ipv6).await?),
        UpstreamRelay::Socks5(proxy_addr) => {
            connect_tcp_via_socks5(proxy_addr, address_ref_from_host(host), port).await
        }
    }
}

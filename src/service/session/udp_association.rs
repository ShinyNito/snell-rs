use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::sleep;

use crate::error::Result;
use crate::service::outbound::{PreparedUdpProxy, PreparedUdpRelay, RelayOptions};
use crate::transport::udp_stream::UdpServerStream;

use super::udp_outbound::{
    relay_proxy_udp_to_snell, relay_snell_to_proxy_udp, relay_snell_to_udp, relay_udp_to_snell,
    wait_proxy_control_closed, write_zero_chunk,
};
use super::udp_socket::{UdpSockets, bind_udp_socket, relay_bind_ip};

pub(crate) const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UdpRelayStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[cfg(test)]
async fn relay_udp_server_stream<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prepared = crate::service::outbound::open_udp(options.clone()).await?;
    relay_udp_server_stream_prepared(stream, options, idle_timeout, prepared).await
}

pub(crate) async fn relay_udp_server_stream_prepared<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
    prepared: PreparedUdpRelay,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match prepared {
        PreparedUdpRelay::Direct => {
            relay_udp_server_stream_direct(stream, options, idle_timeout).await
        }
        PreparedUdpRelay::Proxy(proxy) => {
            relay_udp_server_stream_proxy(stream, options, idle_timeout, proxy).await
        }
    }
}

async fn relay_udp_server_stream_direct<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = stream.into_parts();
    let sockets = UdpSockets::bind(options.ipv6).await?;
    let state = Arc::new(UdpAssociationState::default());

    let end = {
        let snell_to_udp = relay_snell_to_udp(&mut reader, sockets.clone(), options, state.clone());
        let udp_to_snell = relay_udp_to_snell(&mut writer, sockets, state.clone());
        let idle = wait_udp_association_idle(state.clone(), idle_timeout);

        tokio::select! {
            result = snell_to_udp => {
                result?;
                UdpAssociationEnd::SnellClosed
            }
            result = udp_to_snell => {
                result?;
                UdpAssociationEnd::UdpToSnellClosed
            }
            () = idle => {
                tracing::debug!("snell udp stream idle timed out");
                UdpAssociationEnd::Idle
            }
        }
    };

    if matches!(end, UdpAssociationEnd::Idle) {
        // Client zero chunk already means client-side close. Server-originated
        // idle timeout sends zero chunk so the client can stop reading.
        write_zero_chunk(&mut writer).await?;
    }

    Ok(state.stats())
}

async fn relay_udp_server_stream_proxy<R, W>(
    stream: UdpServerStream<R, W>,
    options: RelayOptions,
    idle_timeout: Duration,
    proxy: PreparedUdpProxy,
) -> Result<UdpRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = stream.into_parts();
    let control = proxy.control;
    let relay_addr = proxy.relay_addr;
    let socket = Arc::new(bind_udp_socket(SocketAddr::new(relay_bind_ip(relay_addr), 0)).await?);
    let (mut control_reader, control_writer) = control.into_split();
    let state = Arc::new(UdpAssociationState::default());

    let end = {
        let snell_to_proxy = relay_snell_to_proxy_udp(
            &mut reader,
            socket.clone(),
            relay_addr,
            options,
            state.clone(),
        );
        let proxy_to_snell =
            relay_proxy_udp_to_snell(&mut writer, socket, relay_addr, state.clone());
        let control_closed = wait_proxy_control_closed(&mut control_reader);
        let idle = wait_udp_association_idle(state.clone(), idle_timeout);

        tokio::select! {
            result = snell_to_proxy => {
                result?;
                UdpAssociationEnd::SnellClosed
            }
            result = proxy_to_snell => {
                result?;
                UdpAssociationEnd::UdpToSnellClosed
            }
            result = control_closed => {
                result?;
                UdpAssociationEnd::ProxyControlClosed
            }
            () = idle => {
                tracing::debug!("snell udp stream idle timed out");
                UdpAssociationEnd::Idle
            }
        }
    };
    drop(control_writer);

    if matches!(
        end,
        UdpAssociationEnd::Idle | UdpAssociationEnd::ProxyControlClosed
    ) {
        write_zero_chunk(&mut writer).await?;
    }

    Ok(state.stats())
}

// Polls the activity generation once per timeout window instead of waking on
// every datagram, so the effective idle cutoff lands in [timeout, 2*timeout).
async fn wait_udp_association_idle(state: Arc<UdpAssociationState>, timeout: Duration) {
    let mut observed = state.generation.load(Ordering::Relaxed);
    loop {
        sleep(timeout).await;
        let current = state.generation.load(Ordering::Relaxed);
        if current == observed {
            return;
        }
        observed = current;
    }
}

#[derive(Default)]
pub(super) struct UdpAssociationState {
    generation: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpAssociationEnd {
    SnellClosed,
    UdpToSnellClosed,
    ProxyControlClosed,
    Idle,
}

impl UdpAssociationState {
    pub(super) fn add_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.mark_active();
    }

    pub(super) fn add_received(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.mark_active();
    }

    fn mark_active(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    fn stats(&self) -> UdpRelayStats {
        UdpRelayStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::timeout;

    use super::relay_udp_server_stream;
    use crate::error::Error;
    use crate::protocol::socks5::{
        SocksReply, SocksRequest, SocksTarget, parse_udp_packet as parse_socks_udp_packet,
        write_udp_packet as write_socks_udp_packet,
    };
    use crate::protocol::udp::AddressRef;
    use crate::service::dns::DnsResolver;
    use crate::service::inbound::snell::serve_server_connection;
    use crate::service::inbound::socks5::{
        read_client_request as read_socks_client_request, write_reply_with_bind,
    };
    use crate::service::outbound::RelayOptions;
    use crate::service::test_support::{accept_udp_server_stream, read_udp_response_frame};
    use crate::transport::udp_stream::UdpClientStream;

    fn direct_options(ipv6: bool) -> RelayOptions {
        RelayOptions::direct(ipv6, DnsResolver::system())
    }

    fn socks5_options(ipv6: bool, proxy_addr: std::net::SocketAddr) -> RelayOptions {
        RelayOptions::socks5(ipv6, proxy_addr, DnsResolver::system())
    }

    #[tokio::test]
    async fn udp_server_stream_relays_one_datagram_response() {
        let psk = b"test psk";
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = udp_target.local_addr().unwrap();
        let (client_upload, server_upload) = tokio::io::duplex(4096);
        let (server_download, client_download) = tokio::io::duplex(4096);

        let target = async {
            let mut input = [0u8; 64];
            let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
            assert_eq!(&input[..n], b"query");
            udp_target.send_to(b"answer", peer).await.unwrap();
        };

        let server = async {
            let stream = accept_udp_server_stream(server_upload, server_download, psk)
                .await
                .unwrap();
            relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(1))
                .await
                .unwrap()
        };

        let client = async {
            let (mut reader, mut writer) =
                UdpClientStream::open_io(client_download, client_upload, psk, crate::VERSION_4)
                    .await
                    .unwrap()
                    .into_parts();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    target_addr.port(),
                    b"query",
                )
                .await
                .unwrap();

            let response = read_udp_response_frame(&mut reader).await.unwrap().unwrap();
            assert_eq!(response.payload, b"answer");
            assert_eq!(response.port, target_addr.port());
            writer.write_zero_chunk().await.unwrap();
        };

        let (stats, (), ()) = tokio::join!(server, client, target);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.bytes_sent, 5);
        assert_eq!(stats.bytes_received, 6);
    }

    #[tokio::test]
    async fn udp_stream_does_not_head_of_line_block_on_missing_response() {
        let psk = b"test psk";
        let no_reply_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let no_reply_addr = no_reply_target.local_addr().unwrap();
        let reply_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply_addr = reply_target.local_addr().unwrap();
        let (client_upload, server_upload) = tokio::io::duplex(4096);
        let (server_download, client_download) = tokio::io::duplex(4096);

        let no_reply = async {
            let mut input = [0u8; 64];
            let (n, _) = no_reply_target.recv_from(&mut input).await.unwrap();
            assert_eq!(&input[..n], b"lost");
        };

        let reply = async {
            let mut input = [0u8; 64];
            let (n, peer) = reply_target.recv_from(&mut input).await.unwrap();
            assert_eq!(&input[..n], b"query");
            reply_target.send_to(b"answer", peer).await.unwrap();
        };

        let server = async {
            let stream = accept_udp_server_stream(server_upload, server_download, psk)
                .await
                .unwrap();
            relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(2))
                .await
                .unwrap()
        };

        let client = async {
            let (mut reader, mut writer) =
                UdpClientStream::open_io(client_download, client_upload, psk, crate::VERSION_4)
                    .await
                    .unwrap()
                    .into_parts();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    no_reply_addr.port(),
                    b"lost",
                )
                .await
                .unwrap();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    reply_addr.port(),
                    b"query",
                )
                .await
                .unwrap();

            let response = tokio::time::timeout(
                Duration::from_millis(500),
                read_udp_response_frame(&mut reader),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            assert_eq!(response.payload, b"answer");
            assert_eq!(response.port, reply_addr.port());
            writer.write_zero_chunk().await.unwrap();
        };

        let (stats, (), (), ()) = tokio::join!(server, client, no_reply, reply);
        assert_eq!(stats.packets_sent, 2);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.bytes_sent, 9);
        assert_eq!(stats.bytes_received, 6);
    }

    #[tokio::test]
    async fn udp_server_relays_datagram_via_upstream_socks5() {
        let psk = b"test psk";
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = udp_target.local_addr().unwrap();
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let target = async {
            let mut input = [0u8; 64];
            let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
            assert_eq!(&input[..n], b"query");
            udp_target.send_to(b"answer", peer).await.unwrap();
        };

        let socks = async {
            let (mut control, _) = socks_listener.accept().await.unwrap();
            let request = read_socks_client_request(&mut control).await.unwrap();
            assert_eq!(
                request,
                SocksRequest::UdpAssociate(SocksTarget {
                    host: "0.0.0.0".to_owned(),
                    port: 0,
                })
            );
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay.local_addr().unwrap();
            write_reply_with_bind(&mut control, SocksReply::Succeeded, relay_addr)
                .await
                .unwrap();

            let mut request = [0u8; crate::MAX_PACKET_SIZE + 512];
            let (n, snell_peer) = relay.recv_from(&mut request).await.unwrap();
            let packet = parse_socks_udp_packet(&request[..n]).unwrap();
            assert_eq!(
                packet.address,
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
            );
            assert_eq!(packet.port, target_addr.port());
            assert_eq!(packet.payload, b"query");
            relay.send_to(packet.payload, target_addr).await.unwrap();

            let mut response = [0u8; 64];
            let (n, peer) = relay.recv_from(&mut response).await.unwrap();
            assert_eq!(peer, target_addr);
            let mut socks_response = bytes::BytesMut::new();
            write_socks_udp_packet(
                &mut socks_response,
                AddressRef::Ip(peer.ip()),
                peer.port(),
                &response[..n],
            )
            .unwrap();
            relay.send_to(&socks_response, snell_peer).await.unwrap();

            let mut control_buf = [0; 1];
            let _ = control.read(&mut control_buf).await;
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection(client, psk, socks5_options(false, socks_addr))
                .await
                .unwrap()
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let (mut reader, mut writer) =
                UdpClientStream::open_io(reader, writer, psk, crate::VERSION_4)
                    .await
                    .unwrap()
                    .into_parts();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    target_addr.port(),
                    b"query",
                )
                .await
                .unwrap();

            let response = read_udp_response_frame(&mut reader).await.unwrap().unwrap();
            assert_eq!(response.payload, b"answer");
            assert_eq!(response.port, target_addr.port());
            writer.write_zero_chunk().await.unwrap();
        };

        let ((), (), (), ()) = tokio::join!(target, socks, server, client);
    }

    #[tokio::test]
    async fn udp_upstream_socks5_failure_returns_server_error_before_tunnel_success() {
        let psk = b"test psk";
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let socks = async {
            let (control, _) = socks_listener.accept().await.unwrap();
            drop(control);
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection(client, psk, socks5_options(false, socks_addr)).await
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            assert!(matches!(
                UdpClientStream::open_io(reader, writer, psk, crate::VERSION_4).await,
                Err(Error::Server { code: 1, message }) if message == "connect failed"
            ));
        };

        let ((), server_result, ()) = tokio::join!(socks, server, client);
        assert!(server_result.is_err());
    }

    #[tokio::test]
    async fn udp_upstream_socks5_control_close_ends_association() {
        let psk = b"test psk";
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let socks = async {
            let (mut control, _) = socks_listener.accept().await.unwrap();
            let request = read_socks_client_request(&mut control).await.unwrap();
            assert!(matches!(request, SocksRequest::UdpAssociate(_)));
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            write_reply_with_bind(
                &mut control,
                SocksReply::Succeeded,
                relay.local_addr().unwrap(),
            )
            .await
            .unwrap();
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection(client, psk, socks5_options(false, socks_addr))
                .await
                .unwrap()
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let (mut reader, _) = UdpClientStream::open_io(reader, writer, psk, crate::VERSION_4)
                .await
                .unwrap()
                .into_parts();
            assert!(
                timeout(
                    Duration::from_millis(200),
                    read_udp_response_frame(&mut reader)
                )
                .await
                .unwrap()
                .unwrap()
                .is_none()
            );
        };

        let ((), (), ()) = tokio::join!(socks, server, client);
    }

    #[tokio::test]
    async fn udp_association_idle_timeout_sends_zero_chunk_to_client() {
        let psk = b"test psk";
        let (client_upload, server_upload) = tokio::io::duplex(4096);
        let (server_download, client_download) = tokio::io::duplex(4096);

        let server = async {
            let stream = accept_udp_server_stream(server_upload, server_download, psk)
                .await
                .unwrap();
            relay_udp_server_stream(stream, direct_options(false), Duration::from_millis(20))
                .await
                .unwrap()
        };

        let client = async {
            let (mut reader, _writer) =
                UdpClientStream::open_io(client_download, client_upload, psk, crate::VERSION_4)
                    .await
                    .unwrap()
                    .into_parts();
            assert!(
                timeout(
                    Duration::from_millis(200),
                    read_udp_response_frame(&mut reader)
                )
                .await
                .unwrap()
                .unwrap()
                .is_none()
            );
        };

        let (stats, ()) = tokio::join!(server, client);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
    }

    #[tokio::test]
    async fn client_zero_chunk_ends_udp_association_without_waiting_for_idle() {
        let psk = b"test psk";
        let (client_upload, server_upload) = tokio::io::duplex(4096);
        let (server_download, client_download) = tokio::io::duplex(4096);

        let server = async {
            let stream = accept_udp_server_stream(server_upload, server_download, psk)
                .await
                .unwrap();
            timeout(
                Duration::from_millis(200),
                relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(60)),
            )
            .await
            .unwrap()
            .unwrap()
        };

        let client = async {
            let (_, mut writer) =
                UdpClientStream::open_io(client_download, client_upload, psk, crate::VERSION_4)
                    .await
                    .unwrap()
                    .into_parts();
            writer.write_zero_chunk().await.unwrap();
        };

        let (stats, ()) = tokio::join!(server, client);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
    }

    #[tokio::test]
    async fn udp_to_snell_stops_when_snell_writer_is_closed() {
        let psk = b"test psk";
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = udp_target.local_addr().unwrap();
        let (client_upload, server_upload) = tokio::io::duplex(4096);
        let (server_download, client_download) = tokio::io::duplex(4096);

        let target = async {
            let mut input = [0u8; 64];
            let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
            assert_eq!(&input[..n], b"query");
            udp_target.send_to(b"answer", peer).await.unwrap();
        };

        let server = async {
            let stream = accept_udp_server_stream(server_upload, server_download, psk)
                .await
                .unwrap();
            timeout(
                Duration::from_millis(500),
                relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(60)),
            )
            .await
            .unwrap()
            .unwrap()
        };

        let client = async {
            let (reader, mut writer) =
                UdpClientStream::open_io(client_download, client_upload, psk, crate::VERSION_4)
                    .await
                    .unwrap()
                    .into_parts();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    target_addr.port(),
                    b"query",
                )
                .await
                .unwrap();
            drop(reader);
            writer
        };

        let (stats, writer, ()) = tokio::join!(server, client, target);
        drop(writer);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.bytes_sent, 5);
        assert_eq!(stats.bytes_received, 0);
    }

    #[tokio::test]
    async fn udp_tcp_connection_rejects_ipv6_when_disabled() {
        let psk = b"test psk";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = async {
            let (client, _) = listener.accept().await.unwrap();
            serve_server_connection(client, psk, direct_options(false)).await
        };

        let client = async {
            let stream = TcpStream::connect(server_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let (_, mut writer) = UdpClientStream::open_io(reader, writer, psk, crate::VERSION_4)
                .await
                .unwrap()
                .into_parts();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
                    53,
                    b"query",
                )
                .await
                .unwrap();
        };

        let (server_result, ()) = tokio::join!(server, client);
        assert!(matches!(server_result, Err(Error::Ipv6Disabled)));
    }
}

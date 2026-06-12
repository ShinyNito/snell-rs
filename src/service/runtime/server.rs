use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::VERSION_6;
use crate::error::Result;
use crate::protocol::frame_v6::{V6_SALT_REPLAY_CACHE_CAPACITY, V6SaltReplayCache};
use crate::service::dns::DnsResolver;
use crate::service::inbound::snell::{
    serve_server_connection, serve_server_connection_with_salt_replay_cache,
};
use crate::service::outbound::{RelayOptions, UpstreamRelay};
use crate::service::runtime::config::{ServerConfig, TcpBrutalConfig};
use crate::service::runtime::lifecycle::{
    SHUTDOWN_DRAIN_TIMEOUT, bind_tcp_listener, drain_connection_tasks, log_connection_task_result,
};
use crate::service::runtime::tcp_brutal::{apply_tcp_brutal, validate_tcp_brutal_available};
use crate::service::session::quic_proxy::{
    QUIC_PROXY_SESSION_IDLE_TIMEOUT, serve_quic_proxy_socket,
};

pub async fn bind_configured_tcp_server_with_shutdown(
    config: ServerConfig,
    shutdown: CancellationToken,
) -> Result<()> {
    let options = RelayOptions {
        ipv6: config.ipv6,
        dns_ip_preference: config.dns_ip_preference,
        upstream: UpstreamRelay::from(config.upstream_socks5),
        resolver: DnsResolver::from_config(config.dns)?,
    };
    let listeners = config
        .listen
        .iter()
        .copied()
        .map(|addr| bind_tcp_listener(addr, config.tcp_fast_open))
        .collect::<std::io::Result<Vec<_>>>()?;
    validate_tcp_brutal_available(config.tcp_brutal).await?;
    let v6_salt_replay_cache = (config.version == VERSION_6)
        .then(|| V6SaltReplayCache::new(V6_SALT_REPLAY_CACHE_CAPACITY));
    let tcp_runtime = TcpServerRuntime {
        psk: config.psk.to_vec(),
        version: config.version,
        options,
        tcp_brutal: config.tcp_brutal,
        v6_salt_replay_cache,
        shutdown: shutdown.clone(),
        drain_timeout: SHUTDOWN_DRAIN_TIMEOUT,
    };
    if !config.quic_proxy {
        return serve_tcp_listeners_with_shutdown_and_timeout(listeners, tcp_runtime).await;
    }

    let listen_addr = config.listen[0];
    let listener = listeners
        .into_iter()
        .next()
        .expect("config validation keeps one listener for quic_proxy");
    let udp_socket = UdpSocket::bind(listen_addr).await?;
    let udp = serve_quic_proxy_socket(
        udp_socket,
        config.psk.to_vec(),
        tcp_runtime.options.clone(),
        QUIC_PROXY_SESSION_IDLE_TIMEOUT,
        shutdown.clone(),
    );
    let tcp = serve_tcp_listener_with_shutdown_and_timeout(listener, tcp_runtime);
    tokio::pin!(udp);
    tokio::pin!(tcp);
    tokio::select! {
        result = &mut udp => {
            shutdown.cancel();
            let tcp_result = tcp.await;
            result?;
            tcp_result
        }
        result = &mut tcp => {
            shutdown.cancel();
            let udp_result = udp.await;
            result?;
            udp_result
        }
    }
}

#[derive(Clone)]
pub(crate) struct TcpServerRuntime {
    psk: Vec<u8>,
    version: u8,
    options: RelayOptions,
    tcp_brutal: Option<TcpBrutalConfig>,
    v6_salt_replay_cache: Option<V6SaltReplayCache>,
    shutdown: CancellationToken,
    drain_timeout: Duration,
}

pub(crate) async fn serve_tcp_listeners_with_shutdown_and_timeout(
    listeners: Vec<TcpListener>,
    runtime: TcpServerRuntime,
) -> Result<()> {
    if listeners.len() <= 1 {
        if let Some(listener) = listeners.into_iter().next() {
            return serve_tcp_listener_with_shutdown_and_timeout(listener, runtime).await;
        }
        return Ok(());
    }

    let mut tasks = JoinSet::new();
    let shutdown = runtime.shutdown.clone();
    for listener in listeners {
        tasks.spawn(serve_tcp_listener_with_shutdown_and_timeout(
            listener,
            runtime.clone(),
        ));
    }

    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                shutdown.cancel();
                first_error.get_or_insert(err);
            }
            Err(err) => {
                shutdown.cancel();
                first_error.get_or_insert_with(|| err.into());
            }
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}

pub(crate) async fn serve_tcp_listener_with_shutdown_and_timeout(
    listener: TcpListener,
    runtime: TcpServerRuntime,
) -> Result<()> {
    let TcpServerRuntime {
        psk,
        version,
        options,
        tcp_brutal,
        v6_salt_replay_cache,
        shutdown,
        drain_timeout,
    } = runtime;
    let psk = std::sync::Arc::new(Zeroizing::new(psk));
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            result = listener.accept() => {
                let (client, peer_addr) = result?;
                let psk = psk.clone();
                let options = options.clone();
                let v6_salt_replay_cache = v6_salt_replay_cache.clone();
                tasks.spawn(async move {
                    if let Err(err) = apply_tcp_brutal(&client, tcp_brutal) {
                        tracing::warn!(%err, %peer_addr, "snell tcp_brutal could not be enabled");
                        return;
                    }
                    let result = match v6_salt_replay_cache {
                        Some(cache) => {
                            serve_server_connection_with_salt_replay_cache(
                                client,
                                &psk,
                                version,
                                options,
                                Some(cache),
                            )
                            .await
                        }
                        None => serve_server_connection(client, &psk, version, options).await,
                    };
                    if let Err(err) = result {
                        tracing::debug!(%err, %peer_addr, "snell tcp server connection failed");
                    }
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                log_connection_task_result(result);
            }
        }
    }
    drop(listener);

    drain_connection_tasks(tasks, drain_timeout).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::range::Range;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::{
        TcpServerRuntime, serve_tcp_listener_with_shutdown_and_timeout,
        serve_tcp_listeners_with_shutdown_and_timeout,
    };
    use crate::error::Error;
    use crate::protocol::frame_v6::V6SaltReplayCache;
    use crate::protocol::header::{COMMAND_PING, PROTOCOL_VERSION};
    use crate::protocol::request::ServerReply;
    use crate::protocol::socks5::{SocksReply, SocksRequest, SocksTarget};
    use crate::service::dns::DnsResolver;
    use crate::service::inbound::snell::{
        V6_ERROR_CONNECTION_REFUSED, serve_server_connection,
        serve_server_connection_with_salt_replay_cache, serve_server_connection_with_target_opener,
    };
    use crate::service::inbound::socks5::{read_client_request, write_reply_with_bind};
    use crate::service::outbound::RelayOptions;
    use crate::service::runtime::lifecycle::bind_tcp_listener;
    use crate::transport::tcp_stream::{TcpClientStream, TcpClientWriter};
    use crate::transport::tokio_io::{SnellStreamReader, SnellStreamWriter};
    use crate::{VERSION_4, VERSION_6};

    fn direct_options(ipv6: bool) -> RelayOptions {
        RelayOptions::direct(ipv6, DnsResolver::system())
    }

    fn socks5_options(ipv6: bool, proxy_addr: std::net::SocketAddr) -> RelayOptions {
        RelayOptions::socks5(ipv6, proxy_addr, DnsResolver::system())
    }

    fn tcp_server_runtime(
        psk: &[u8],
        version: u8,
        options: RelayOptions,
        shutdown: CancellationToken,
        drain_timeout: Duration,
    ) -> TcpServerRuntime {
        TcpServerRuntime {
            psk: psk.to_vec(),
            version,
            options,
            tcp_brutal: None,
            v6_salt_replay_cache: None,
            shutdown,
            drain_timeout,
        }
    }

    async fn write_client_payload<W>(
        writer: &mut TcpClientWriter<W>,
        payload: &[u8],
    ) -> crate::error::Result<usize>
    where
        W: AsyncWrite + Unpin,
    {
        let mut plain = payload;
        Ok(writer
            .write_payload_from_reader(&mut plain)
            .await?
            .unwrap_or(0))
    }

    #[tokio::test]
    async fn serve_server_connection_relays_to_connected_target() {
        let psk = b"test psk";
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let echo = async {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection_with_target_opener(
                client,
                psk,
                VERSION_4,
                direct_options(true),
                move |target, _options| async move {
                    assert_eq!(target.host, "example.com");
                    assert_eq!(target.port, 443);
                    Ok(TcpStream::connect(echo_addr).await?)
                },
            )
            .await
            .unwrap()
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let snell =
                TcpClientStream::open_io(reader, writer, psk, "example.com", 443, VERSION_4, false)
                    .await
                    .unwrap();
            let (mut snell_reader, mut snell_writer) = snell.into_split();

            write_client_payload(&mut snell_writer, b"ping")
                .await
                .unwrap();
            snell_writer.close_write().await.unwrap();

            let payload = snell_reader.read_payload_chunk().await.unwrap().unwrap();
            assert_eq!(payload, b"pong");
            let len = payload.len();
            snell_reader.consume_payload_chunk(len);
            assert!(snell_reader.read_payload_chunk().await.unwrap().is_none());
        };

        let ((), (), ()) = tokio::join!(server, client, echo);
    }

    #[tokio::test]
    async fn serve_server_connection_relays_v6_to_connected_target() {
        let psk = b"test psk";
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let echo = async {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"v6 ping");
            stream.write_all(b"v6 pong").await.unwrap();
            stream.shutdown().await.unwrap();
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection_with_target_opener(
                client,
                psk,
                VERSION_6,
                direct_options(true),
                move |target, _options| async move {
                    assert_eq!(target.host, "v6.example.com");
                    assert_eq!(target.port, 443);
                    Ok(TcpStream::connect(echo_addr).await?)
                },
            )
            .await
            .unwrap()
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let snell = TcpClientStream::open_io(
                reader,
                writer,
                psk,
                "v6.example.com",
                443,
                VERSION_6,
                false,
            )
            .await
            .unwrap();
            let (mut snell_reader, mut snell_writer) = snell.into_split();

            write_client_payload(&mut snell_writer, b"v6 ping")
                .await
                .unwrap();
            snell_writer.close_write().await.unwrap();

            let payload = snell_reader.read_payload_chunk().await.unwrap().unwrap();
            assert_eq!(payload, b"v6 pong");
            let len = payload.len();
            snell_reader.consume_payload_chunk(len);
            assert!(snell_reader.read_payload_chunk().await.unwrap().is_none());
        };

        let ((), (), ()) = tokio::join!(server, client, echo);
    }

    #[tokio::test]
    async fn serve_server_connection_handles_v6_ping() {
        let psk = b"test psk";
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection(client, psk, VERSION_6, direct_options(false))
                .await
                .unwrap()
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (snell_reader_io, snell_writer_io) = stream.into_split();
            let mut snell_writer = SnellStreamWriter::new(snell_writer_io, psk, VERSION_6).unwrap();
            snell_writer
                .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
                .await
                .unwrap();

            let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, VERSION_6).unwrap();
            assert_eq!(
                snell_reader.read_server_reply().await.unwrap(),
                ServerReply::Pong
            );
        };

        let ((), ()) = tokio::join!(server, client);
    }

    #[tokio::test]
    async fn serve_server_connection_v6_rejects_replayed_client_salt() {
        let psk = b"test psk";
        let salt = [0x44; 16];
        let cache = V6SaltReplayCache::new(16);
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let server = async {
            let (first, _) = snell_listener.accept().await.unwrap();
            serve_server_connection_with_salt_replay_cache(
                first,
                psk,
                VERSION_6,
                direct_options(false),
                Some(cache.clone()),
            )
            .await
            .unwrap();

            let (second, _) = snell_listener.accept().await.unwrap();
            assert!(matches!(
                serve_server_connection_with_salt_replay_cache(
                    second,
                    psk,
                    VERSION_6,
                    direct_options(false),
                    Some(cache),
                )
                .await,
                Err(Error::SaltReplay)
            ));
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (snell_reader_io, snell_writer_io) = stream.into_split();
            let mut writer =
                SnellStreamWriter::new_with_v6_salt(snell_writer_io, psk, salt).unwrap();
            writer
                .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
                .await
                .unwrap();
            let mut reader = SnellStreamReader::new(snell_reader_io, psk, VERSION_6).unwrap();
            assert_eq!(reader.read_server_reply().await.unwrap(), ServerReply::Pong);

            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (snell_reader_io, snell_writer_io) = stream.into_split();
            let mut writer =
                SnellStreamWriter::new_with_v6_salt(snell_writer_io, psk, salt).unwrap();
            writer
                .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
                .await
                .unwrap();
            let mut reader = SnellStreamReader::new(snell_reader_io, psk, VERSION_6).unwrap();
            let err = reader.read_server_reply().await.unwrap_err();
            assert!(err.is_closed_io(), "{err:?}");
        };

        let ((), ()) = tokio::join!(server, client);
    }

    #[tokio::test]
    async fn serve_server_connection_relays_via_upstream_socks5() {
        let psk = b"test psk";
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let echo = async {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        };

        let socks = async {
            let (mut client, _) = socks_listener.accept().await.unwrap();
            let request = read_client_request(&mut client).await.unwrap();
            assert_eq!(
                request,
                SocksRequest::Connect(SocksTarget {
                    host: "example.com".to_owned(),
                    port: 443,
                })
            );
            let mut upstream = TcpStream::connect(echo_addr).await.unwrap();
            write_reply_with_bind(
                &mut client,
                SocksReply::Succeeded,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await
            .unwrap();
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .unwrap();
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection(client, psk, VERSION_4, socks5_options(true, socks_addr))
                .await
                .unwrap()
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let snell =
                TcpClientStream::open_io(reader, writer, psk, "example.com", 443, VERSION_4, false)
                    .await
                    .unwrap();
            let (mut snell_reader, mut snell_writer) = snell.into_split();

            write_client_payload(&mut snell_writer, b"ping")
                .await
                .unwrap();
            snell_writer.close_write().await.unwrap();

            let payload = snell_reader.read_payload_chunk().await.unwrap().unwrap();
            assert_eq!(payload, b"pong");
            let len = payload.len();
            snell_reader.consume_payload_chunk(len);
            assert!(snell_reader.read_payload_chunk().await.unwrap().is_none());
        };

        let ((), (), (), ()) = tokio::join!(echo, socks, server, client);
    }

    #[tokio::test]
    async fn serve_server_connection_closes_when_upstream_socks5_rejects_after_fast_open() {
        let psk = b"test psk";
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let socks = async {
            let (mut client, _) = socks_listener.accept().await.unwrap();
            let request = read_client_request(&mut client).await.unwrap();
            assert!(matches!(request, SocksRequest::Connect(_)));
            write_reply_with_bind(
                &mut client,
                SocksReply::GeneralFailure,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await
            .unwrap();
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection(client, psk, VERSION_4, socks5_options(true, socks_addr)).await
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let snell =
                TcpClientStream::open_io(reader, writer, psk, "example.com", 443, VERSION_4, false)
                    .await
                    .unwrap();
            let (mut snell_reader, _) = snell.into_split();
            assert!(
                timeout(Duration::from_secs(1), snell_reader.read_payload_chunk())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none()
            );
        };

        let ((), server_result, ()) = tokio::join!(socks, server, client);
        assert!(matches!(server_result, Err(Error::Socks5Reply(1))));
    }

    #[tokio::test]
    async fn serve_server_connection_fast_open_accepts_before_target_connects() {
        let psk = b"test psk";
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();
        let (connect_tx, connect_rx) = oneshot::channel();

        let echo = async {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"early");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        };

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            let mut connect_rx = Some(connect_rx);
            serve_server_connection_with_target_opener(
                client,
                psk,
                VERSION_4,
                direct_options(true),
                move |target, _options| {
                    let connect_rx = connect_rx.take().unwrap();
                    async move {
                        assert_eq!(target.host, "example.com");
                        assert_eq!(target.port, 443);
                        connect_rx.await.unwrap();
                        Ok(TcpStream::connect(echo_addr).await?)
                    }
                },
            )
            .await
            .unwrap()
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (snell_reader_io, snell_writer_io) = stream.into_split();
            let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, VERSION_4).unwrap();
            let mut snell_writer = SnellStreamWriter::new(snell_writer_io, psk, VERSION_4).unwrap();
            snell_writer
                .write_tcp_request("example.com", 443, false)
                .await
                .unwrap();

            assert_eq!(
                timeout(Duration::from_millis(200), snell_reader.read_server_reply())
                    .await
                    .unwrap()
                    .unwrap(),
                ServerReply::Tunnel {
                    payload_span: Range { start: 1, end: 1 },
                    payload: b"",
                }
            );

            snell_writer.write_test_frame(b"early").await.unwrap();
            snell_writer.write_zero_chunk().await.unwrap();
            connect_tx.send(()).unwrap();

            let payload = snell_reader.read_frame_payload().await.unwrap();
            assert_eq!(payload, b"pong");
            assert!(matches!(
                snell_reader.read_frame_payload().await,
                Err(Error::ZeroChunk)
            ));
        };

        let ((), (), ()) = tokio::join!(echo, server, client);
    }

    #[tokio::test]
    async fn serve_tcp_listener_with_shutdown_stops_accepting_connections() {
        let psk = b"test psk";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(serve_tcp_listener_with_shutdown_and_timeout(
            listener,
            tcp_server_runtime(
                psk,
                VERSION_4,
                direct_options(true),
                shutdown.clone(),
                Duration::from_millis(100),
            ),
        ));

        shutdown.cancel();
        timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert!(TcpStream::connect(addr).await.is_err());
    }

    #[tokio::test]
    async fn serve_tcp_listeners_accepts_connections_on_each_listener() {
        let psk = b"test psk";
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_addr = second.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(serve_tcp_listeners_with_shutdown_and_timeout(
            vec![first, second],
            TcpServerRuntime {
                v6_salt_replay_cache: Some(V6SaltReplayCache::new(16)),
                ..tcp_server_runtime(
                    psk,
                    VERSION_6,
                    direct_options(false),
                    shutdown.clone(),
                    Duration::from_millis(100),
                )
            },
        ));

        async fn ping(addr: std::net::SocketAddr, psk: &[u8]) {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (snell_reader_io, snell_writer_io) = stream.into_split();
            let mut writer = SnellStreamWriter::new(snell_writer_io, psk, VERSION_6).unwrap();
            writer
                .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
                .await
                .unwrap();
            let mut reader = SnellStreamReader::new(snell_reader_io, psk, VERSION_6).unwrap();
            assert_eq!(reader.read_server_reply().await.unwrap(), ServerReply::Pong);
        }

        ping(first_addr, psk).await;
        ping(second_addr, psk).await;
        shutdown.cancel();
        timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn serve_tcp_listener_with_shutdown_drains_active_connection() {
        let psk = b"test psk";
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let (echo_ready_tx, echo_ready_rx) = oneshot::channel();
        let (echo_continue_tx, echo_continue_rx) = oneshot::channel();
        let server = tokio::spawn(serve_tcp_listener_with_shutdown_and_timeout(
            snell_listener,
            tcp_server_runtime(
                psk,
                VERSION_4,
                direct_options(true),
                shutdown.clone(),
                Duration::from_secs(1),
            ),
        ));

        let echo = async {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"ping");
            echo_ready_tx.send(()).unwrap();
            echo_continue_rx.await.unwrap();
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (reader, writer) = stream.into_split();
            let snell = TcpClientStream::open_io(
                reader,
                writer,
                psk,
                "127.0.0.1",
                echo_addr.port(),
                VERSION_4,
                false,
            )
            .await
            .unwrap();
            let (mut snell_reader, mut snell_writer) = snell.into_split();

            write_client_payload(&mut snell_writer, b"ping")
                .await
                .unwrap();
            snell_writer.close_write().await.unwrap();
            echo_ready_rx.await.unwrap();

            shutdown.cancel();
            echo_continue_tx.send(()).unwrap();

            let payload = snell_reader.read_payload_chunk().await.unwrap().unwrap();
            assert_eq!(payload, b"pong");
            let len = payload.len();
            snell_reader.consume_payload_chunk(len);
            assert!(snell_reader.read_payload_chunk().await.unwrap().is_none());
        };

        let ((), ()) = tokio::join!(client, echo);
        timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn bind_tcp_listener_accepts_tcp_fast_open_flag() {
        let listener = bind_tcp_listener("127.0.0.1:0".parse().unwrap(), true).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut input = [0; 4];
            stream.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"ping");
            stream.write_all(b"pong").await.unwrap();
        };

        let client = async {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"ping").await.unwrap();

            let mut output = [0; 4];
            stream.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"pong");
        };

        let ((), ()) = tokio::join!(server, client);
    }

    #[tokio::test]
    async fn connect_target_rejects_ipv6_literal_when_disabled() {
        let resolver = crate::service::dns::DnsResolver::system();
        let result = crate::service::outbound::direct::open_direct_tcp(
            "::1",
            443,
            false,
            crate::service::dns::DnsIpPreference::Default,
            &resolver,
        )
        .await;

        assert!(matches!(
            result,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    #[tokio::test]
    async fn serve_server_connection_closes_after_fast_open_connect_failure() {
        let psk = b"test psk";
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection_with_target_opener(
                client,
                psk,
                VERSION_4,
                direct_options(true),
                |_target, _options| async move {
                    Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "test refusal",
                    )))
                },
            )
            .await
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (snell_reader_io, snell_writer_io) = stream.into_split();
            let mut snell_writer = SnellStreamWriter::new(snell_writer_io, psk, VERSION_4).unwrap();
            snell_writer
                .write_tcp_request("blocked.example", 443, false)
                .await
                .unwrap();

            let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, VERSION_4).unwrap();
            assert_eq!(
                snell_reader.read_server_reply().await.unwrap(),
                ServerReply::Tunnel {
                    payload_span: Range { start: 1, end: 1 },
                    payload: b"",
                }
            );
            let err = snell_reader.read_frame_payload().await.unwrap_err();
            assert!(err.is_closed_io(), "{err:?}");
        };

        let (server_result, ()) = tokio::join!(server, client);
        assert!(matches!(server_result, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn serve_server_connection_v6_returns_error_reply_on_connect_failure() {
        let psk = b"test psk";
        let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let snell_addr = snell_listener.local_addr().unwrap();

        let server = async {
            let (client, _) = snell_listener.accept().await.unwrap();
            serve_server_connection_with_target_opener(
                client,
                psk,
                VERSION_6,
                direct_options(true),
                |_target, _options| async move {
                    Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "test refusal",
                    )))
                },
            )
            .await
        };

        let client = async {
            let stream = TcpStream::connect(snell_addr).await.unwrap();
            let (snell_reader_io, snell_writer_io) = stream.into_split();
            let mut snell_writer = SnellStreamWriter::new(snell_writer_io, psk, VERSION_6).unwrap();
            snell_writer
                .write_tcp_request("blocked.example", 443, false)
                .await
                .unwrap();

            let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, VERSION_6).unwrap();
            assert_eq!(
                snell_reader.read_server_reply().await.unwrap(),
                ServerReply::Error {
                    code: V6_ERROR_CONNECTION_REFUSED,
                    message: "test refusal",
                }
            );
        };

        let (server_result, ()) = tokio::join!(server, client);
        assert!(matches!(server_result, Err(Error::Io(_))));
    }
}

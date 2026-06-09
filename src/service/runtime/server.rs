use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::service::inbound::snell::serve_server_connection;
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
        upstream: UpstreamRelay::from(config.upstream_socks5),
    };
    let listener = bind_tcp_listener(config.listen, config.tcp_fast_open)?;
    validate_tcp_brutal_available(config.tcp_brutal).await?;
    if !config.quic_proxy {
        return serve_tcp_listener_with_shutdown_and_timeout(
            listener,
            config.psk.to_vec(),
            options,
            config.tcp_brutal,
            shutdown,
            SHUTDOWN_DRAIN_TIMEOUT,
        )
        .await;
    }

    let udp_socket = UdpSocket::bind(config.listen).await?;
    let udp = serve_quic_proxy_socket(
        udp_socket,
        config.psk.to_vec(),
        options,
        QUIC_PROXY_SESSION_IDLE_TIMEOUT,
        shutdown.clone(),
    );
    let tcp = serve_tcp_listener_with_shutdown_and_timeout(
        listener,
        config.psk.to_vec(),
        options,
        config.tcp_brutal,
        shutdown.clone(),
        SHUTDOWN_DRAIN_TIMEOUT,
    );
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

pub(crate) async fn serve_tcp_listener_with_shutdown_and_timeout(
    listener: TcpListener,
    psk: Vec<u8>,
    options: RelayOptions,
    tcp_brutal: Option<TcpBrutalConfig>,
    shutdown: CancellationToken,
    drain_timeout: Duration,
) -> Result<()> {
    let psk = Zeroizing::new(psk);
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            result = listener.accept() => {
                let (client, peer_addr) = result?;
                let psk = psk.clone();
                tasks.spawn(async move {
                    if let Err(err) = apply_tcp_brutal(&client, tcp_brutal) {
                        tracing::warn!(%err, %peer_addr, "snell tcp_brutal could not be enabled");
                        return;
                    }
                    if let Err(err) = serve_server_connection(client, &psk, options).await {
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
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::serve_tcp_listener_with_shutdown_and_timeout;
    use crate::VERSION_4;
    use crate::error::Error;
    use crate::protocol::request::ServerReply;
    use crate::protocol::socks5::{SocksReply, SocksRequest, SocksTarget};
    use crate::service::inbound::snell::{
        serve_server_connection, serve_server_connection_with_target_opener,
    };
    use crate::service::inbound::socks5::{read_client_request, write_reply_with_bind};
    use crate::service::outbound::{RelayOptions, UpstreamRelay};
    use crate::service::runtime::lifecycle::{bind_tcp_listener, bind_tcp_listener_resolved};
    use crate::transport::tcp_stream::{TcpClientStream, TcpClientWriter};
    use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};

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
                RelayOptions::default(),
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
            serve_server_connection(
                client,
                psk,
                RelayOptions {
                    ipv6: true,
                    upstream: UpstreamRelay::Socks5(socks_addr),
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
            serve_server_connection(
                client,
                psk,
                RelayOptions {
                    ipv6: true,
                    upstream: UpstreamRelay::Socks5(socks_addr),
                },
            )
            .await
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
                RelayOptions::default(),
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
            let mut snell_reader = V4StreamReader::new(snell_reader_io, psk).unwrap();
            let mut snell_writer = V4StreamWriter::new(snell_writer_io, psk).unwrap();
            snell_writer
                .write_tcp_request("example.com", 443, VERSION_4, false)
                .await
                .unwrap();

            assert_eq!(
                timeout(Duration::from_millis(200), snell_reader.read_server_reply())
                    .await
                    .unwrap()
                    .unwrap(),
                ServerReply::Tunnel {
                    payload_offset: 1,
                    payload: b"",
                }
            );

            snell_writer.write_frame(b"early").await.unwrap();
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
            psk.to_vec(),
            RelayOptions::default(),
            None,
            shutdown.clone(),
            Duration::from_millis(100),
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
            psk.to_vec(),
            RelayOptions {
                ipv6: true,
                ..RelayOptions::default()
            },
            None,
            shutdown.clone(),
            Duration::from_secs(1),
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
    async fn bind_tcp_listener_resolved_binds_with_shared_socket_options() {
        let listener = bind_tcp_listener_resolved("127.0.0.1:0", false)
            .await
            .unwrap();
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
        let result = crate::service::outbound::direct::open_direct_tcp("::1", 443, false).await;

        assert!(matches!(
            result,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput
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
                RelayOptions::default(),
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
            let mut snell_writer = V4StreamWriter::new(snell_writer_io, psk).unwrap();
            snell_writer
                .write_tcp_request("blocked.example", 443, VERSION_4, false)
                .await
                .unwrap();

            let mut snell_reader = V4StreamReader::new(snell_reader_io, psk).unwrap();
            assert_eq!(
                snell_reader.read_server_reply().await.unwrap(),
                ServerReply::Tunnel {
                    payload_offset: 1,
                    payload: b"",
                }
            );
            let err = snell_reader.read_frame_payload().await.unwrap_err();
            assert!(err.is_closed_io(), "{err:?}");
        };

        let (server_result, ()) = tokio::join!(server, client);
        assert!(matches!(server_result, Err(Error::Io(_))));
    }
}

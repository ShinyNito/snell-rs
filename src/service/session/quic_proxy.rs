use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::MAX_PACKET_SIZE;
use crate::error::Result;
use crate::protocol::quic_proxy::{decode_init_datagram, is_quic_looking};
use crate::service::outbound::{
    QuicProxyRelay, RelayOptions, open_quic_udp, run_quic_proxy_response_session,
};

pub const QUIC_PROXY_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) async fn serve_quic_proxy_socket(
    socket: UdpSocket,
    psk: Vec<u8>,
    options: RelayOptions,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> Result<()> {
    let psk = Zeroizing::new(psk);
    let socket = Arc::new(socket);
    let mut sessions = HashMap::<SocketAddr, QuicProxySession>::new();
    let mut buf = BytesMut::with_capacity(MAX_PACKET_SIZE + 512);
    let cleanup = sleep(idle_timeout);
    tokio::pin!(cleanup);

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            recv_result = socket.recv_buf_from(&mut buf) => {
                let (n, client_addr) = recv_result?;
                if n == 0 {
                    buf.clear();
                    continue;
                }
                let first_byte = buf[0];
                if sessions
                    .get(&client_addr)
                    .is_some_and(|session| session.response_task.is_finished())
                {
                    sessions.remove(&client_addr);
                }
                if let Some(session) = sessions.get_mut(&client_addr) {
                    session.last_activity = Instant::now();
                    let send_result = if is_quic_looking(first_byte) {
                        session.relay.send_payload(&buf[..n]).await
                    } else {
                        let (payload_start, payload_len) = match decode_init_datagram(&psk, &mut buf[..n]) {
                            Ok(init) => (init.payload_offset, init.payload.len()),
                            Err(err) => {
                                tracing::debug!(%err, %client_addr, "ignored invalid quic proxy datagram");
                                buf.clear();
                                continue;
                            }
                        };
                        let payload_end = payload_start + payload_len;
                        session.relay.send_payload(&buf[payload_start..payload_end]).await
                    };
                    buf.clear();
                    if let Err(err) = send_result {
                        tracing::debug!(%err, %client_addr, "quic proxy session send failed");
                        session.response_task.abort();
                        sessions.remove(&client_addr);
                    }
                    continue;
                }

                if is_quic_looking(first_byte) {
                    tracing::debug!(%client_addr, "dropped raw quic proxy packet without session");
                    buf.clear();
                    continue;
                }

                let (host, port, payload_start, payload_len) = {
                    let init = match decode_init_datagram(&psk, &mut buf[..n]) {
                        Ok(init) => init,
                        Err(err) => {
                            tracing::debug!(%err, %client_addr, "ignored invalid quic proxy init");
                            buf.clear();
                            continue;
                        }
                    };
                    (
                        init.host.to_owned(),
                        init.port,
                        init.payload_offset,
                        init.payload.len(),
                    )
                };
                let mut first_payload = buf.split_off(payload_start);
                first_payload.truncate(payload_len);
                let first_payload = first_payload.freeze();
                buf.clear();
                let mut relay = open_quic_udp(host, port, options).await?;
                let response_task = tokio::spawn(run_quic_proxy_response_session(
                    socket.clone(),
                    client_addr,
                    relay.response_relay(),
                ));
                if let Err(err) = relay.send_payload(&first_payload).await {
                    response_task.abort();
                    tracing::debug!(%err, %client_addr, "quic proxy initial payload send failed");
                    continue;
                }
                sessions.insert(client_addr, QuicProxySession {
                    relay,
                    response_task,
                    last_activity: Instant::now(),
                });
            }
            _ = &mut cleanup => {
                let now = Instant::now();
                sessions.retain(|_, session| {
                    let keep = now.duration_since(session.last_activity) <= idle_timeout
                        && !session.response_task.is_finished();
                    if !keep {
                        session.response_task.abort();
                    }
                    keep
                });
                cleanup.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
        }
    }

    drain_quic_proxy_sessions(sessions).await;
    Ok(())
}

struct QuicProxySession {
    relay: QuicProxyRelay,
    response_task: JoinHandle<Result<()>>,
    last_activity: Instant,
}

async fn drain_quic_proxy_sessions(sessions: HashMap<SocketAddr, QuicProxySession>) {
    for session in sessions.values() {
        session.response_task.abort();
    }
    for (client_addr, session) in sessions {
        match session.response_task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::debug!(%err, %client_addr, "quic proxy response task failed during shutdown");
            }
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                tracing::debug!(%err, %client_addr, "quic proxy response task ended unexpectedly");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::serve_quic_proxy_socket;
    use crate::protocol::quic_proxy::encode_init_datagram;
    use crate::protocol::socks5::{
        SocksReply, SocksRequest, SocksTarget, parse_udp_packet as parse_socks_udp_packet,
        write_udp_packet as write_socks_udp_packet,
    };
    use crate::protocol::udp::AddressRef;
    use crate::service::inbound::socks5::{
        read_client_request as read_socks_client_request, write_reply_with_bind,
    };
    use crate::service::outbound::{RelayOptions, UpstreamRelay};

    #[tokio::test]
    async fn quic_proxy_init_session_forwards_raw_and_response() {
        let psk = b"test psk";
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            RelayOptions {
                ipv6: false,
                ..RelayOptions::default()
            },
            Duration::from_secs(1),
            shutdown.clone(),
        ));

        let mut plaintext = BytesMut::new();
        let mut wire = BytesMut::new();
        encode_init_datagram(
            psk,
            "127.0.0.1",
            target_addr.port(),
            b"\xc0first",
            &mut plaintext,
            &mut wire,
        )
        .unwrap();
        client.send_to(&wire, server_addr).await.unwrap();

        let mut buf = [0; 128];
        let (n, peer) = timeout(Duration::from_secs(1), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\xc0first");

        client.send_to(b"\xc0second", server_addr).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(1), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\xc0second");

        target.send_to(b"\x40reply", peer).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\x40reply");
        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn quic_proxy_drops_raw_packet_without_session() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            b"test psk".to_vec(),
            RelayOptions::default(),
            Duration::from_secs(1),
            shutdown.clone(),
        ));

        client.send_to(b"\xc0raw", server_addr).await.unwrap();
        let mut buf = [0; 32];
        assert!(
            timeout(Duration::from_millis(80), client.recv_from(&mut buf))
                .await
                .is_err()
        );
        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn quic_proxy_rejects_bad_psk_init() {
        let psk = b"test psk";
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            RelayOptions::default(),
            Duration::from_secs(1),
            shutdown.clone(),
        ));

        let mut plaintext = BytesMut::new();
        let mut wire = BytesMut::new();
        encode_init_datagram(
            b"wrong psk",
            "127.0.0.1",
            target_addr.port(),
            b"\xc0first",
            &mut plaintext,
            &mut wire,
        )
        .unwrap();
        client.send_to(&wire, server_addr).await.unwrap();

        let mut buf = [0; 32];
        assert!(
            timeout(Duration::from_millis(80), target.recv_from(&mut buf))
                .await
                .is_err()
        );
        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn quic_proxy_session_idle_timeout_drops_session() {
        let psk = b"test psk";
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            RelayOptions {
                ipv6: false,
                ..RelayOptions::default()
            },
            Duration::from_millis(30),
            shutdown.clone(),
        ));

        let mut plaintext = BytesMut::new();
        let mut wire = BytesMut::new();
        encode_init_datagram(
            psk,
            "127.0.0.1",
            target_addr.port(),
            b"\xc0first",
            &mut plaintext,
            &mut wire,
        )
        .unwrap();
        client.send_to(&wire, server_addr).await.unwrap();

        let mut buf = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\xc0first");

        tokio::time::sleep(Duration::from_millis(100)).await;
        client
            .send_to(b"\xc0after-idle", server_addr)
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(80), target.recv_from(&mut buf))
                .await
                .is_err()
        );
        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn quic_proxy_uses_upstream_socks5_udp_associate() {
        let psk = b"test psk";
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            RelayOptions {
                upstream: UpstreamRelay::Socks5(socks_addr),
                ..RelayOptions::default()
            },
            Duration::from_secs(1),
            shutdown.clone(),
        ));

        let socks = async {
            let (mut control, _) = socks_listener.accept().await.unwrap();
            assert_eq!(
                read_socks_client_request(&mut control).await.unwrap(),
                SocksRequest::UdpAssociate(SocksTarget {
                    host: "0.0.0.0".to_owned(),
                    port: 0,
                })
            );
            write_reply_with_bind(&mut control, SocksReply::Succeeded, relay_addr)
                .await
                .unwrap();

            let mut buf = [0; 256];
            let (n, peer) = relay.recv_from(&mut buf).await.unwrap();
            let packet = parse_socks_udp_packet(&buf[..n]).unwrap();
            assert_eq!(packet.payload, b"\xc0first");
            assert_eq!(packet.port, 443);

            let mut response = BytesMut::new();
            write_socks_udp_packet(
                &mut response,
                AddressRef::Domain("example.com"),
                443,
                b"\x40reply",
            )
            .unwrap();
            relay.send_to(&response, peer).await.unwrap();

            let mut control_buf = [0; 1];
            let _ = control.read(&mut control_buf).await;
        };

        let client_io = async {
            let mut plaintext = BytesMut::new();
            let mut wire = BytesMut::new();
            encode_init_datagram(
                psk,
                "example.com",
                443,
                b"\xc0first",
                &mut plaintext,
                &mut wire,
            )
            .unwrap();
            client.send_to(&wire, server_addr).await.unwrap();

            let mut buf = [0; 64];
            let (n, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], b"\x40reply");
        };

        let ((), ()) = tokio::join!(socks, client_io);
        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

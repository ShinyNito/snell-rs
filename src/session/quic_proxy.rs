use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use zeroize::Zeroizing;

use crate::MAX_PACKET_SIZE;
use crate::error::Result;
use crate::protocol::quic_proxy::{decode_init_datagram, is_quic_looking};
use crate::proxy::outbound::{RelayOptions, open_quic_udp, run_quic_proxy_response_session};

pub const QUIC_PROXY_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-session queue of payloads awaiting the session task. A full queue drops
/// the datagram (UDP loss semantics) instead of stalling every other client on
/// the shared socket.
const SESSION_QUEUE_CAPACITY: usize = 256;
const RECV_BUFFER_CAPACITY: usize = MAX_PACKET_SIZE + 512;
const PAYLOAD_SCRATCH_CAPACITY: usize = 64 * 1024;

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
    let mut buf = BytesMut::with_capacity(RECV_BUFFER_CAPACITY);
    let mut scratch = BytesMut::with_capacity(PAYLOAD_SCRATCH_CAPACITY);
    let cleanup = sleep(idle_timeout);
    tokio::pin!(cleanup);

    loop {
        buf.clear();
        tokio::select! {
            () = shutdown.cancelled() => break,
            recv_result = socket.recv_buf_from(&mut buf) => {
                let (n, client_addr) = recv_result?;
                if n == 0 {
                    continue;
                }
                let first_byte = buf[0];
                if sessions
                    .get(&client_addr)
                    .is_some_and(QuicProxySession::is_closed)
                {
                    sessions.remove(&client_addr);
                }
                if let Some(session) = sessions.get_mut(&client_addr) {
                    let payload = if is_quic_looking(first_byte) {
                        copy_payload(&mut scratch, &buf[..n])
                    } else {
                        let init = match decode_init_datagram(&psk, &mut buf[..n]) {
                            Ok(init) => init,
                            Err(err) => {
                                tracing::debug!(%err, %client_addr, "ignored invalid quic proxy datagram");
                                continue;
                            }
                        };
                        let span = init.payload_span;
                        copy_payload(&mut scratch, &buf[span.start..span.end])
                    };
                    session.last_activity = Instant::now();
                    match session.queue.try_send(payload) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::debug!(%client_addr, "quic proxy session queue full, dropped datagram");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            sessions.remove(&client_addr);
                        }
                    }
                    continue;
                }

                if is_quic_looking(first_byte) {
                    tracing::debug!(%client_addr, "dropped raw quic proxy packet without session");
                    continue;
                }

                let (host, port, first_payload) = {
                    let init = match decode_init_datagram(&psk, &mut buf[..n]) {
                        Ok(init) => init,
                        Err(err) => {
                            tracing::debug!(%err, %client_addr, "ignored invalid quic proxy init");
                            continue;
                        }
                    };
                    let span = init.payload_span;
                    (
                        init.host.to_owned(),
                        init.port,
                        copy_payload(&mut scratch, &buf[span.start..span.end]),
                    )
                };
                let (queue, payloads) = mpsc::channel(SESSION_QUEUE_CAPACITY);
                let task = tokio::spawn(run_quic_proxy_session(
                    socket.clone(),
                    client_addr,
                    host,
                    port,
                    options.clone(),
                    first_payload,
                    payloads,
                ));
                sessions.insert(client_addr, QuicProxySession {
                    queue,
                    task,
                    last_activity: Instant::now(),
                });
            }
            _ = &mut cleanup => {
                let now = Instant::now();
                sessions.retain(|_, session| {
                    let keep = now.duration_since(session.last_activity) <= idle_timeout
                        && !session.is_closed();
                    if !keep {
                        session.task.abort();
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

/// Owns the upstream relay for one client address. Opening the relay (DNS,
/// socket binds, optional SOCKS5 handshake) and every upstream send happen
/// here, so a slow or stalled session never blocks the shared receive loop.
async fn run_quic_proxy_session(
    server_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    host: String,
    port: u16,
    options: RelayOptions,
    first_payload: Bytes,
    mut payloads: mpsc::Receiver<Bytes>,
) {
    let mut relay = match open_quic_udp(host, port, options).await {
        Ok(relay) => relay,
        Err(err) => {
            tracing::debug!(%err, %client_addr, "quic proxy session open failed");
            return;
        }
    };
    // Abort-on-drop: if this session task is itself aborted (idle eviction,
    // shutdown drain), the response task must not outlive it holding sockets.
    let mut response_task = AbortOnDropHandle::new(tokio::spawn(run_quic_proxy_response_session(
        server_socket,
        client_addr,
        relay.response_relay(),
    )));

    let send_payloads = async {
        let mut payload = first_payload;
        loop {
            if let Err(err) = relay.send_payload(&payload).await {
                tracing::debug!(%err, %client_addr, "quic proxy session send failed");
                return;
            }
            match payloads.recv().await {
                Some(next) => payload = next,
                None => return,
            }
        }
    };
    tokio::pin!(send_payloads);

    tokio::select! {
        () = &mut send_payloads => {
            response_task.abort();
            log_quic_proxy_response_task_result(client_addr, response_task.await);
        }
        result = &mut response_task => {
            log_quic_proxy_response_task_result(client_addr, result);
        }
    }
}

fn log_quic_proxy_response_task_result(
    client_addr: SocketAddr,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::debug!(%err, %client_addr, "quic proxy response task failed");
        }
        Err(err) if err.is_cancelled() => {}
        Err(err) => {
            tracing::debug!(%err, %client_addr, "quic proxy response task ended unexpectedly");
        }
    }
}

struct QuicProxySession {
    queue: mpsc::Sender<Bytes>,
    task: JoinHandle<()>,
    last_activity: Instant,
}

impl QuicProxySession {
    fn is_closed(&self) -> bool {
        self.queue.is_closed() || self.task.is_finished()
    }
}

/// Copies one datagram payload out of the shared receive buffer so it can be
/// queued to the session task. Carves `Bytes` out of a large scratch block to
/// amortize allocations across packets.
fn copy_payload(scratch: &mut BytesMut, payload: &[u8]) -> Bytes {
    if scratch.capacity() < payload.len() {
        *scratch = BytesMut::with_capacity(PAYLOAD_SCRATCH_CAPACITY.max(payload.len()));
    }
    scratch.extend_from_slice(payload);
    scratch.split().freeze()
}

async fn drain_quic_proxy_sessions(sessions: HashMap<SocketAddr, QuicProxySession>) {
    for session in sessions.values() {
        session.task.abort();
    }
    for (client_addr, session) in sessions {
        match session.task.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                tracing::debug!(%err, %client_addr, "quic proxy session task ended unexpectedly");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::{Bytes, BytesMut};
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::{run_quic_proxy_session, serve_quic_proxy_socket};
    use crate::net::dns::DnsResolver;
    use crate::protocol::quic_proxy::encode_init_datagram;
    use crate::protocol::socks5::{
        SocksReply, SocksRequest, SocksTarget, parse_udp_packet as parse_socks_udp_packet,
        write_udp_packet as write_socks_udp_packet,
    };
    use crate::protocol::udp::AddressRef;
    use crate::proxy::outbound::RelayOptions;
    use crate::proxy::socks5::inbound::{
        read_client_request as read_socks_client_request, write_reply_with_bind,
    };
    use crate::test_support::{TEST_PSK, test_tcp_listener, test_udp_socket};

    fn direct_options(ipv6: bool) -> RelayOptions {
        RelayOptions::direct(ipv6, DnsResolver::system())
    }

    fn socks5_options(proxy_addr: std::net::SocketAddr) -> RelayOptions {
        RelayOptions::socks5(true, proxy_addr, DnsResolver::system())
    }

    #[tokio::test]
    async fn quic_proxy_init_session_forwards_raw_and_response() {
        let psk = TEST_PSK;
        let target = test_udp_socket().await;
        let target_addr = target.local_addr().unwrap();
        let server = test_udp_socket().await;
        let server_addr = server.local_addr().unwrap();
        let client = test_udp_socket().await;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            direct_options(false),
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
        let server = test_udp_socket().await;
        let server_addr = server.local_addr().unwrap();
        let client = test_udp_socket().await;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            TEST_PSK.to_vec(),
            direct_options(true),
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
        let psk = TEST_PSK;
        let target = test_udp_socket().await;
        let target_addr = target.local_addr().unwrap();
        let server = test_udp_socket().await;
        let server_addr = server.local_addr().unwrap();
        let client = test_udp_socket().await;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            direct_options(true),
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
    async fn quic_proxy_open_failure_keeps_socket_loop_alive() {
        let psk = TEST_PSK;
        let target = test_udp_socket().await;
        let target_addr = target.local_addr().unwrap();
        let server = test_udp_socket().await;
        let server_addr = server.local_addr().unwrap();
        let bad_client = test_udp_socket().await;
        let good_client = test_udp_socket().await;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            direct_options(false),
            Duration::from_secs(1),
            shutdown.clone(),
        ));

        let mut plaintext = BytesMut::new();
        let mut wire = BytesMut::new();
        encode_init_datagram(psk, "::1", 443, b"\xc0bad", &mut plaintext, &mut wire).unwrap();
        bad_client.send_to(&wire, server_addr).await.unwrap();

        plaintext.clear();
        wire.clear();
        encode_init_datagram(
            psk,
            "127.0.0.1",
            target_addr.port(),
            b"\xc0good",
            &mut plaintext,
            &mut wire,
        )
        .unwrap();
        good_client.send_to(&wire, server_addr).await.unwrap();

        let mut buf = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\xc0good");

        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn quic_proxy_response_failure_closes_session_task() {
        let target = test_udp_socket().await;
        let target_addr = target.local_addr().unwrap();
        let server = test_udp_socket().await;
        let client_addr = "[::1]:12345".parse().unwrap();
        let (queue, payloads) = mpsc::channel(1);
        let task = tokio::spawn(run_quic_proxy_session(
            std::sync::Arc::new(server),
            client_addr,
            "127.0.0.1".to_owned(),
            target_addr.port(),
            direct_options(false),
            Bytes::from_static(b"\xc0first"),
            payloads,
        ));

        let mut buf = [0; 128];
        let (n, peer) = timeout(Duration::from_secs(1), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\xc0first");
        target.send_to(b"\x40reply", peer).await.unwrap();

        timeout(Duration::from_secs(1), task)
            .await
            .expect("response failure should end the session")
            .unwrap();
        assert!(queue.is_closed());
    }

    #[tokio::test]
    async fn quic_proxy_session_idle_timeout_drops_session() {
        let psk = TEST_PSK;
        let target = test_udp_socket().await;
        let target_addr = target.local_addr().unwrap();
        let server = test_udp_socket().await;
        let server_addr = server.local_addr().unwrap();
        let client = test_udp_socket().await;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            direct_options(false),
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
        let psk = TEST_PSK;
        let socks_listener = test_tcp_listener().await;
        let socks_addr = socks_listener.local_addr().unwrap();
        let relay = test_udp_socket().await;
        let relay_addr = relay.local_addr().unwrap();
        let server = test_udp_socket().await;
        let server_addr = server.local_addr().unwrap();
        let client = test_udp_socket().await;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_quic_proxy_socket(
            server,
            psk.to_vec(),
            socks5_options(socks_addr),
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

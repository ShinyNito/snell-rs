use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::{run_quic_proxy_flow, serve_quic_proxy_socket};
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
async fn quic_proxy_init_flow_forwards_raw_and_response() {
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
async fn quic_proxy_drops_raw_packet_without_flow() {
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
async fn quic_proxy_response_failure_closes_flow_task() {
    let target = test_udp_socket().await;
    let target_addr = target.local_addr().unwrap();
    let server = test_udp_socket().await;
    let client_addr = "[::1]:12345".parse().unwrap();
    let (queue, payloads) = mpsc::channel(1);
    let task = tokio::spawn(run_quic_proxy_flow(
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
        .expect("response failure should end the flow")
        .unwrap();
    assert!(queue.is_closed());
}

#[tokio::test]
async fn quic_proxy_flow_idle_timeout_drops_flow() {
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

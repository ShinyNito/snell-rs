use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use snell_protocol::socks5;
use snell_protocol::{
    Address, AddressRef, Error, MAX_PACKET_SIZE, ProtocolFlavor, ProtocolSelection, Psk, V4Decoder,
    V4Encoder, udp_request_len,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::pool::{PooledCodec, PooledConn, ReusePool};
use crate::replay::ReplayCache;
use crate::server::handle_server;
use crate::session::{new_udp_encode, write_tunnel, write_udp_request, write_udp_setup};
use crate::{ClientConfig, ServerConfig, UdpOptions, serve_client, serve_server};

const PSK: &[u8] = b"0123456789abcdef";

struct Pair {
    socks: SocketAddr,
    _stop_client: oneshot::Sender<()>,
    _stop_server: oneshot::Sender<()>,
}

async fn start_pair(version: ProtocolFlavor, outbound: Outbound) -> Pair {
    start_pair_reuse(version, outbound, false, None, None).await
}

async fn start_pair_reuse(
    version: ProtocolFlavor,
    outbound: Outbound,
    reuse: bool,
    pool: Option<ReusePool>,
    tcp_brutal: Option<crate::TcpBrutal>,
) -> Pair {
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = client_listener.local_addr().unwrap();

    let (stop_server, server_rx) = oneshot::channel();
    let (stop_client, client_rx) = oneshot::channel();

    let server_cfg = ServerConfig {
        listen: server_addr,
        psk: psk.clone(),
        selection: ProtocolSelection::Exact(version),
        outbound,
        udp: UdpOptions::default(),
        tcp_brutal,
    };
    tokio::spawn(async move {
        let _ = serve_server(server_listener, server_cfg, async {
            let _ = server_rx.await;
        })
        .await;
    });

    let client_cfg = ClientConfig {
        listen: socks,
        server: server_addr,
        psk,
        version,
        reuse,
        pool,
        udp: UdpOptions::default(),
    };
    tokio::spawn(async move {
        let _ = serve_client(client_listener, client_cfg, async {
            let _ = client_rx.await;
        })
        .await;
    });

    Pair {
        socks,
        _stop_client: stop_client,
        _stop_server: stop_server,
    }
}

async fn socks5_echo(socks: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    timeout(Duration::from_secs(5), socks5_echo_inner(socks, payload))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "echo timed out"))?
}

async fn socks5_echo_inner(socks: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await?;
        }
        io::Result::Ok(())
    });

    let mut client = TcpStream::connect(socks).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await?;
    assert_eq!(method, [0x05, 0x00]);

    let std::net::SocketAddr::V4(echo_v4) = echo_addr else {
        panic!("echo must be ipv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&echo_v4.ip().octets());
    request.extend_from_slice(&echo_v4.port().to_be_bytes());
    client.write_all(&request).await?;

    let mut reply_head = [0u8; 4];
    client.read_exact(&mut reply_head).await?;
    assert_eq!(reply_head[0], 0x05);
    assert_eq!(reply_head[1], 0x00);
    let mut bind = [0u8; 6];
    client.read_exact(&mut bind).await?;

    client.write_all(payload).await?;
    client.shutdown().await?;
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await?;
    server.await.map_err(io::Error::other)??;
    Ok(echoed)
}

#[tokio::test]
async fn v4_echo_roundtrip() {
    let pair = start_pair(ProtocolFlavor::V4, Outbound::Direct).await;
    let payload = b"phase-5-v4";
    let echoed = socks5_echo(pair.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn v5_echo_roundtrip() {
    let pair = start_pair(ProtocolFlavor::V5, Outbound::Direct).await;
    let payload = b"phase-5-v5";
    let echoed = socks5_echo(pair.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn v6_shaped_echo_roundtrip() {
    let pair = start_pair(ProtocolFlavor::V6Shaped, Outbound::Direct).await;
    let payload = b"phase-5-v6-shaped";
    let echoed = socks5_echo(pair.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn v6_unshaped_echo_roundtrip() {
    let pair = start_pair(ProtocolFlavor::V6Unshaped, Outbound::Direct).await;
    let payload = b"phase-5-v6-unshaped";
    let echoed = socks5_echo(pair.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn large_stream_echo() {
    let pair = start_pair(ProtocolFlavor::V4, Outbound::Direct).await;
    let payload = vec![0x5a; 256 * 1024];
    let echoed = socks5_echo(pair.socks, &payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn half_close_echo() {
    let pair = start_pair(ProtocolFlavor::V4, Outbound::Direct).await;
    let payload = b"half-close";
    let echoed = socks5_echo(pair.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn socks5_outbound_echo() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = proxy.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = socks5_proxy_once(&mut stream).await;
            });
        }
    });
    let pair = start_pair(ProtocolFlavor::V4, Outbound::Socks5 { server: proxy_addr }).await;
    let payload = b"via-socks5-outbound";
    let echoed = socks5_echo(pair.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

async fn socks5_proxy_once(stream: &mut TcpStream) -> io::Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    let mut dest = [0u8; 6];
    stream.read_exact(&mut dest).await?;
    let ip = std::net::Ipv4Addr::new(dest[0], dest[1], dest[2], dest[3]);
    let port = u16::from_be_bytes([dest[4], dest[5]]);
    let mut remote = TcpStream::connect((ip, port)).await?;
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    tokio::io::copy_bidirectional(stream, &mut remote).await?;
    Ok(())
}

#[tokio::test]
async fn handshake_timeout() {
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let (stop_server, server_rx) = oneshot::channel::<()>();
    let cfg = ServerConfig {
        listen: server_addr,
        psk,
        selection: ProtocolSelection::Exact(ProtocolFlavor::V4),
        outbound: Outbound::Direct,
        udp: UdpOptions::default(),
        tcp_brutal: None,
    };
    tokio::spawn(async move {
        let _ = serve_server(server_listener, cfg, async {
            let _ = server_rx.await;
        })
        .await;
    });
    let mut idle = TcpStream::connect(server_addr).await.unwrap();
    let started = Instant::now();
    let result = timeout(Duration::from_secs(16), idle.read_u8()).await;
    drop(stop_server);
    assert!(
        matches!(result, Ok(Err(_))),
        "peer must close around 15s; test timeout is not success: {result:?}"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(14),
        "closed too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "must be well under 20s: {elapsed:?}"
    );
}

#[tokio::test]
async fn socks5_reply_when_snell_closes_after_dial() {
    let snell_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let snell_addr = snell_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = snell_listener.accept().await else {
                break;
            };
            drop(stream);
        }
    });

    let psk = Psk::new(PSK.to_vec()).unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = client_listener.local_addr().unwrap();
    let (stop_client, client_rx) = oneshot::channel::<()>();
    let cfg = ClientConfig {
        listen: socks,
        server: snell_addr,
        psk,
        version: ProtocolFlavor::V4,
        reuse: false,
        pool: None,
        udp: UdpOptions::default(),
    };
    tokio::spawn(async move {
        let _ = serve_client(client_listener, cfg, async {
            let _ = client_rx.await;
        })
        .await;
    });

    let mut client = TcpStream::connect(socks).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 9])
        .await
        .unwrap();
    let mut reply_head = [0u8; 4];
    timeout(Duration::from_secs(2), client.read_exact(&mut reply_head))
        .await
        .expect("SOCKS5 failure reply must arrive before the local handshake timeout")
        .unwrap();
    assert_eq!(reply_head[0], 0x05);
    assert_ne!(reply_head[1], 0x00);
    drop(stop_client);
}

#[tokio::test]
async fn socks5_outbound_slow_handshake_cannot_delay_tunnel_past_15s() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = proxy.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            });
        }
    });

    let pair = start_pair(ProtocolFlavor::V4, Outbound::Socks5 { server: proxy_addr }).await;
    let mut client = TcpStream::connect(pair.socks).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 9])
        .await
        .unwrap();

    let started = Instant::now();
    let mut reply_head = [0u8; 4];
    let result = timeout(Duration::from_secs(16), client.read_exact(&mut reply_head)).await;
    let elapsed = started.elapsed();
    assert!(
        result.is_ok(),
        "Tunnel wait must finish within 16s, not ~20s: {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(14),
        "failed too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(18),
        "SOCKS5 outbound must not stack onto 20s: {elapsed:?}"
    );
    if result.unwrap().is_ok() {
        assert_eq!(reply_head[0], 0x05);
        assert_ne!(reply_head[1], 0x00);
    }
}

#[test]
fn tcp_hot_path_has_no_channel_or_flush() {
    let sources = [
        include_str!("session.rs"),
        include_str!("client.rs"),
        include_str!("server.rs"),
        include_str!("bufio.rs"),
        include_str!("outbound.rs"),
        include_str!("auto.rs"),
        include_str!("pool.rs"),
    ];
    for src in sources {
        assert!(!src.contains("mpsc"), "TCP path must not use mpsc");
        assert!(
            !src.contains("tokio::sync::channel"),
            "TCP path must not use channels"
        );
        assert!(
            !src.contains(".flush("),
            "TCP path must not unconditionally flush"
        );
        assert!(
            !src.contains("Vec::with_capacity"),
            "TCP path must not allocate per record"
        );
    }
}

struct Counted {
    socks: SocketAddr,
    accepts: Arc<AtomicUsize>,
    _stop_client: oneshot::Sender<()>,
}

async fn start_counted(
    version: ProtocolFlavor,
    selection: ProtocolSelection,
    reuse: bool,
    pool: Option<ReusePool>,
) -> Counted {
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = client_listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let (stop_client, client_rx) = oneshot::channel();

    let server_cfg = ServerConfig {
        listen: server_addr,
        psk: psk.clone(),
        selection,
        outbound: Outbound::Direct,
        udp: UdpOptions::default(),
        tcp_brutal: None,
    };
    let kdf = Arc::new(KdfLimiter::new());
    let replay = Arc::new(ReplayCache::new());
    let accepts_server = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = server_listener.accept().await else {
                break;
            };
            accepts_server.fetch_add(1, Ordering::SeqCst);
            let server_cfg = server_cfg.clone();
            let kdf = kdf.clone();
            let replay = replay.clone();
            tokio::spawn(async move {
                let _ = handle_server(stream, server_cfg, kdf, replay).await;
            });
        }
    });

    let client_cfg = ClientConfig {
        listen: socks,
        server: server_addr,
        psk,
        version,
        reuse,
        pool,
        udp: UdpOptions::default(),
    };
    tokio::spawn(async move {
        let _ = serve_client(client_listener, client_cfg, async {
            let _ = client_rx.await;
        })
        .await;
    });

    Counted {
        socks,
        accepts,
        _stop_client: stop_client,
    }
}

async fn reuse_two_echoes(version: ProtocolFlavor) {
    let counted = start_counted(version, ProtocolSelection::Exact(version), true, None).await;
    for i in 0..2 {
        let payload = format!("reuse-{version:?}-{i}").into_bytes();
        let echoed = socks5_echo(counted.socks, &payload).await.unwrap();
        assert_eq!(echoed, payload);
    }
    assert_eq!(counted.accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn v4_reuse_two_echoes_one_snell_conn() {
    reuse_two_echoes(ProtocolFlavor::V4).await;
}

#[tokio::test]
async fn v5_reuse_two_echoes_one_snell_conn() {
    reuse_two_echoes(ProtocolFlavor::V5).await;
}

#[tokio::test]
async fn v6_shaped_reuse_two_echoes_one_snell_conn() {
    reuse_two_echoes(ProtocolFlavor::V6Shaped).await;
}

#[tokio::test]
async fn v6_unshaped_reuse_two_echoes_one_snell_conn() {
    reuse_two_echoes(ProtocolFlavor::V6Unshaped).await;
}

#[tokio::test]
async fn reuse_false_opens_two_snell_conns() {
    let counted = start_counted(
        ProtocolFlavor::V4,
        ProtocolSelection::Exact(ProtocolFlavor::V4),
        false,
        None,
    )
    .await;
    for i in 0..2 {
        let payload = format!("oneshot-{i}").into_bytes();
        let echoed = socks5_echo(counted.socks, &payload).await.unwrap();
        assert_eq!(echoed, payload);
    }
    assert_eq!(counted.accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn stale_pool_retries_once() {
    let pool = ReusePool::new();
    let dummy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dummy_addr = dummy.local_addr().unwrap();
    let stream = TcpStream::connect(dummy_addr).await.unwrap();
    let peer = dummy.accept().await.unwrap().0;
    drop(peer);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let encoder = V4Encoder::os(&psk).unwrap();
    let decoder = V4Decoder::new(psk);
    let _ = pool.put(PooledConn {
        stream,
        codec: PooledCodec::V4 { encoder, decoder },
    });

    let counted = start_counted(
        ProtocolFlavor::V4,
        ProtocolSelection::Exact(ProtocolFlavor::V4),
        true,
        Some(pool),
    )
    .await;
    let payload = b"stale-retry";
    let echoed = socks5_echo(counted.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
    assert_eq!(counted.accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn error_connections_are_not_returned_to_pool() {
    let pool = ReusePool::new();
    let pair = start_pair_reuse(
        ProtocolFlavor::V4,
        Outbound::Direct,
        true,
        Some(pool.clone()),
        None,
    )
    .await;
    let mut client = TcpStream::connect(pair.socks).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1])
        .await
        .unwrap();
    let mut reply_head = [0u8; 4];
    timeout(Duration::from_secs(5), client.read_exact(&mut reply_head))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply_head[0], 0x05);
    assert_ne!(reply_head[1], 0x00);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(pool.len(), 0);
}

#[tokio::test]
async fn auto_server_accepts_v4() {
    let counted = start_counted(ProtocolFlavor::V4, ProtocolSelection::Auto, false, None).await;
    let payload = b"auto-v4";
    let echoed = socks5_echo(counted.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn auto_server_accepts_v6_shaped() {
    let counted = start_counted(
        ProtocolFlavor::V6Shaped,
        ProtocolSelection::Auto,
        false,
        None,
    )
    .await;
    let payload = b"auto-v6-shaped";
    let echoed = socks5_echo(counted.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn exact_v4_does_not_accept_v6_shaped() {
    let counted = start_counted(
        ProtocolFlavor::V6Shaped,
        ProtocolSelection::Exact(ProtocolFlavor::V4),
        false,
        None,
    )
    .await;
    let mut client = TcpStream::connect(counted.socks).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 9])
        .await
        .unwrap();
    let mut reply_head = [0u8; 4];
    timeout(Duration::from_secs(5), client.read_exact(&mut reply_head))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply_head[0], 0x05);
    assert_ne!(reply_head[1], 0x00);
}

#[test]
fn exact_mode_does_not_probe() {
    let src = include_str!("server.rs");
    let calls = src.matches("detect_protocol(").count();
    assert_eq!(calls, 1, "detect_protocol must be called once, from Auto");
    let auto_idx = src.find("ProtocolSelection::Auto").expect("auto arm");
    assert!(
        src[auto_idx..].contains("detect_protocol("),
        "auto arm must probe"
    );
}

#[tokio::test]
async fn early_payload_over_64kib_is_rejected() {
    use snell_protocol::{
        Address, EncodeBuffer, MAX_CONNECT_REQUEST_LEN, SERVER_EARLY_PAYLOAD_MAX,
        encode_connect_request,
    };

    let psk = Psk::new(PSK.to_vec()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig {
        listen: addr,
        psk: psk.clone(),
        selection: ProtocolSelection::Exact(ProtocolFlavor::V4),
        outbound: Outbound::Direct,
        udp: UdpOptions::default(),
        tcp_brutal: None,
    };
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_server(
            stream,
            cfg,
            Arc::new(KdfLimiter::new()),
            Arc::new(ReplayCache::new()),
        )
        .await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut encoder = V4Encoder::os(&psk).unwrap();
    let mut encode = EncodeBuffer::new(snell_protocol::ENCODE_BUFFER_MAX);
    let dest = Address::from("127.0.0.1:9".parse::<SocketAddr>().unwrap());
    let mut req = [0u8; MAX_CONNECT_REQUEST_LEN];
    let n = encode_connect_request(&mut req, dest.as_view(), false).unwrap();
    let mut plain = req[..n].to_vec();
    plain.extend(std::iter::repeat_n(b'x', SERVER_EARLY_PAYLOAD_MAX + 1));
    let mut offset = 0;
    while offset < plain.len() {
        let mut reservation = encoder
            .reserve(&mut encode, &[], plain.len() - offset)
            .unwrap();
        let take = reservation.capacity().min(plain.len() - offset);
        reservation.payload_mut()[..take].copy_from_slice(&plain[offset..offset + take]);
        reservation.seal(take).unwrap();
        offset += take;
    }
    tokio::io::AsyncWriteExt::write_all(&mut client, encode.pending())
        .await
        .unwrap();

    let result = timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, Err(crate::SessionError::EarlyPayloadTooLarge)),
        "{result:?}"
    );
}

#[tokio::test]
async fn unavailable_tcp_brutal_does_not_break_connections() {
    let params = crate::TcpBrutal {
        send_mbps: 100,
        cwnd_gain: 15,
    };
    let pair = start_pair_reuse(
        ProtocolFlavor::V4,
        Outbound::Direct,
        false,
        None,
        Some(params),
    )
    .await;
    let payload = b"tcp-brutal-fallback";
    let echoed = socks5_echo(pair.socks, payload).await.unwrap();
    assert_eq!(echoed, payload);
}

struct UdpPair {
    socks: SocketAddr,
    client_udp: UdpOptions,
    _server_udp: UdpOptions,
    _stop_client: oneshot::Sender<()>,
    _stop_server: oneshot::Sender<()>,
}

async fn start_pair_udp(
    version: ProtocolFlavor,
    outbound: Outbound,
    client_udp: UdpOptions,
    server_udp: UdpOptions,
) -> UdpPair {
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = client_listener.local_addr().unwrap();
    let (stop_server, server_rx) = oneshot::channel();
    let (stop_client, client_rx) = oneshot::channel();
    let server_cfg = ServerConfig {
        listen: server_addr,
        psk: psk.clone(),
        selection: ProtocolSelection::Exact(version),
        outbound,
        udp: server_udp.clone(),
        tcp_brutal: None,
    };
    tokio::spawn(async move {
        let _ = serve_server(server_listener, server_cfg, async {
            let _ = server_rx.await;
        })
        .await;
    });
    let client_cfg = ClientConfig {
        listen: socks,
        server: server_addr,
        psk,
        version,
        reuse: false,
        pool: None,
        udp: client_udp.clone(),
    };
    tokio::spawn(async move {
        let _ = serve_client(client_listener, client_cfg, async {
            let _ = client_rx.await;
        })
        .await;
    });
    UdpPair {
        socks,
        client_udp,
        _server_udp: server_udp,
        _stop_client: stop_client,
        _stop_server: stop_server,
    }
}

async fn spawn_udp_echo() -> io::Result<SocketAddr> {
    let echo = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = echo.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, peer)) = echo.recv_from(&mut buf).await else {
                break;
            };
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });
    Ok(addr)
}

async fn socks5_udp_associate(socks: SocketAddr) -> io::Result<(TcpStream, SocketAddr, UdpSocket)> {
    let mut tcp = TcpStream::connect(socks).await?;
    tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    tcp.read_exact(&mut method).await?;
    assert_eq!(method, [0x05, 0x00]);
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut reply_head = [0u8; 4];
    tcp.read_exact(&mut reply_head).await?;
    assert_eq!(reply_head[0], 0x05);
    if reply_head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "udp associate failed: {}",
            reply_head[1]
        )));
    }
    assert_eq!(reply_head[3], 0x01);
    let mut rest = [0u8; 6];
    tcp.read_exact(&mut rest).await?;
    let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
    let port = u16::from_be_bytes([rest[4], rest[5]]);
    let relay = SocketAddr::from((ip, port));
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    Ok((tcp, relay, udp))
}

fn encode_socks_udp(dest: SocketAddr, frag: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 32 + payload.len()];
    let n = socks5::encode_udp_packet(&mut buf, frag, AddressRef::Ip(dest), payload).unwrap();
    buf.truncate(n);
    buf
}

async fn socks5_udp_roundtrip(
    socks: SocketAddr,
    echo: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let (_tcp, relay, client) = socks5_udp_associate(socks).await?;
    let packet = encode_socks_udp(echo, 0, payload);
    client.send_to(&packet, relay).await?;
    let mut buf = [0u8; 65535];
    let (n, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "udp echo timed out"))??;
    let parsed = socks5::parse_udp_packet(&buf[..n]).unwrap();
    assert_eq!(parsed.frag, 0);
    Ok(parsed.payload.to_vec())
}

async fn udp_echo_version(version: ProtocolFlavor, payload: &[u8]) {
    let pair = start_pair_udp(
        version,
        Outbound::Direct,
        UdpOptions::default(),
        UdpOptions::default(),
    )
    .await;
    let echo = spawn_udp_echo().await.unwrap();
    let got = socks5_udp_roundtrip(pair.socks, echo, payload)
        .await
        .unwrap();
    assert_eq!(got, payload);
}

#[tokio::test]
async fn v4_udp_echo_roundtrip() {
    udp_echo_version(ProtocolFlavor::V4, b"phase-7-v4").await;
}

#[tokio::test]
async fn v5_udp_echo_roundtrip() {
    udp_echo_version(ProtocolFlavor::V5, b"phase-7-v5").await;
}

#[tokio::test]
async fn v6_shaped_udp_echo_roundtrip() {
    udp_echo_version(ProtocolFlavor::V6Shaped, b"phase-7-v6-shaped").await;
}

#[tokio::test]
async fn v6_unshaped_udp_echo_roundtrip() {
    udp_echo_version(ProtocolFlavor::V6Unshaped, b"phase-7-v6-unshaped").await;
}

#[test]
fn v4_udp_request_with_max_packet_payload_exceeds_slot() {
    let dest = AddressRef::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));
    let needed = udp_request_len(dest, MAX_PACKET_SIZE).unwrap();
    assert!(
        needed > MAX_PACKET_SIZE,
        "payload {MAX_PACKET_SIZE} plus UDP request header must miss the v4 slot ({needed} > {MAX_PACKET_SIZE})"
    );
}

#[tokio::test]
async fn write_udp_request_rejects_payload_that_misses_v4_slot() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            match server.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let psk = Psk::new(PSK.to_vec()).unwrap();
    let mut encoder = V4Encoder::os(&psk).unwrap();
    let mut encode = new_udp_encode();
    write_udp_setup(&mut encoder, &mut encode, &mut client)
        .await
        .unwrap();
    write_tunnel(&mut encoder, &mut encode, &mut client)
        .await
        .unwrap();
    let dest = Address::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));
    let payload = vec![0xab; MAX_PACKET_SIZE];
    let error = write_udp_request(
        &mut encoder,
        &mut encode,
        &mut client,
        dest.as_view(),
        &payload,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, SessionError::Protocol(Error::PayloadTooLarge)),
        "expected PayloadTooLarge, got {error:?}"
    );
}

#[tokio::test]
async fn udp_frag_nonzero_is_dropped() {
    let pair = start_pair_udp(
        ProtocolFlavor::V4,
        Outbound::Direct,
        UdpOptions::default(),
        UdpOptions::default(),
    )
    .await;
    let echo = spawn_udp_echo().await.unwrap();
    let (_tcp, relay, client) = socks5_udp_associate(pair.socks).await.unwrap();
    let packet = encode_socks_udp(echo, 1, b"frag");
    client.send_to(&packet, relay).await.unwrap();
    let mut buf = [0u8; 64];
    let result = timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
    assert!(result.is_err(), "FRAG != 0 must not be forwarded");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(pair.client_udp.metrics.frag_dropped.load(Ordering::Relaxed) >= 1);
}

#[tokio::test]
async fn udp_idle_expires_association() {
    let mut client_udp = UdpOptions::default();
    client_udp.limits.idle = Duration::from_millis(80);
    let pair = start_pair_udp(
        ProtocolFlavor::V4,
        Outbound::Direct,
        client_udp,
        UdpOptions::default(),
    )
    .await;
    let echo = spawn_udp_echo().await.unwrap();
    let (_tcp, relay, client) = socks5_udp_associate(pair.socks).await.unwrap();
    let packet = encode_socks_udp(echo, 0, b"idle");
    client.send_to(&packet, relay).await.unwrap();
    let mut buf = [0u8; 65535];
    let (n, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let parsed = socks5::parse_udp_packet(&buf[..n]).unwrap();
    assert_eq!(parsed.payload, b"idle");
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(pair.client_udp.metrics.idle_expired.load(Ordering::Relaxed) >= 1);
    assert_eq!(
        pair.client_udp.metrics.associations.load(Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn udp_associations_stay_capped() {
    let mut client_udp = UdpOptions::default();
    client_udp.limits.max_associations = 4;
    let pair = start_pair_udp(
        ProtocolFlavor::V4,
        Outbound::Direct,
        client_udp,
        UdpOptions::default(),
    )
    .await;
    let echo = spawn_udp_echo().await.unwrap();
    let (_tcp, relay, _) = socks5_udp_associate(pair.socks).await.unwrap();
    let packet = encode_socks_udp(echo, 0, b"cap");
    for _ in 0..16 {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&packet, relay).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let live = pair.client_udp.metrics.associations.load(Ordering::Relaxed);
    assert!(live <= 4, "associations={live}");
    assert!(pair.client_udp.metrics.map_full.load(Ordering::Relaxed) >= 1);
}

#[tokio::test]
async fn udp_socks5_outbound_echo() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = proxy.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = socks5_udp_proxy_once(stream).await;
            });
        }
    });
    let pair = start_pair_udp(
        ProtocolFlavor::V4,
        Outbound::Socks5 { server: proxy_addr },
        UdpOptions::default(),
        UdpOptions::default(),
    )
    .await;
    let echo = spawn_udp_echo().await.unwrap();
    let got = socks5_udp_roundtrip(pair.socks, echo, b"via-socks5-udp")
        .await
        .unwrap();
    assert_eq!(got, b"via-socks5-udp");
}

async fn socks5_udp_proxy_once(mut stream: TcpStream) -> io::Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    match req[3] {
        0x01 => {
            let mut dest = [0u8; 6];
            stream.read_exact(&mut dest).await?;
        }
        0x04 => {
            let mut dest = [0u8; 18];
            stream.read_exact(&mut dest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut rest).await?;
        }
        _ => {}
    }
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let bind = udp.local_addr()?;
    let std::net::SocketAddr::V4(v4) = bind else {
        panic!("proxy bind ipv4");
    };
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&v4.ip().octets());
    reply.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&reply).await?;
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let mut ctrl = [0u8; 1];
    loop {
        tokio::select! {
            result = udp.recv_from(&mut buf) => {
                let (n, peer) = result?;
                let packet = match socks5::parse_udp_packet(&buf[..n]) {
                    Ok(packet) if packet.frag == 0 => packet,
                    _ => continue,
                };
                let AddressRef::Ip(dest) = packet.destination else {
                    continue;
                };
                let payload = packet.payload.to_vec();
                udp.send_to(&payload, dest).await?;
                let (rn, from) = udp.recv_from(&mut buf).await?;
                let n = socks5::encode_udp_packet(
                    &mut out,
                    0,
                    AddressRef::Ip(from),
                    &buf[..rn],
                )
                .unwrap();
                udp.send_to(&out[..n], peer).await?;
            }
            n = stream.read(&mut ctrl) => {
                if n? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

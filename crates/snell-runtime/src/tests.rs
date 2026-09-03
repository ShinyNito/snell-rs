use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use snell_protocol::{ProtocolFlavor, Psk};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::outbound::Outbound;
use crate::{ClientConfig, ServerConfig, serve_client, serve_server};

const PSK: &[u8] = b"0123456789abcdef";

struct Pair {
    socks: SocketAddr,
    _stop_client: oneshot::Sender<()>,
    _stop_server: oneshot::Sender<()>,
}

async fn start_pair(version: ProtocolFlavor, outbound: Outbound) -> Pair {
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
        version,
        outbound,
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
        version: ProtocolFlavor::V4,
        outbound: Outbound::Direct,
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

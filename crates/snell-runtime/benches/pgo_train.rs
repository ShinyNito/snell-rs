//! PGO training workload for the release pipeline's profile-generate pass
//! (`.github/scripts/pgo-release-build.sh`).
//!
//! This is not a benchmark for comparing numbers; it is a representative
//! traffic mix chosen to cover the hot paths of a deployed proxy:
//!
//! - server-side auto-detect (v4 and v6-shaped) and exact selection,
//! - several concurrent TCP connections mixing bulk streams with small and
//!   mid-size ping-pong records,
//! - UDP ping-pong and windowed bursts on an established association,
//! - connection churn through the reuse pool (dial+KDF miss, then hits).
//!
//! V5 shares the v4 record codec, so the v4 pass covers it.
//!
//! Run: `cargo bench -p snell-runtime --bench pgo_train`

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use snell_protocol::socks5;
use snell_protocol::{AddressRef, ProtocolFlavor, ProtocolSelection, Psk};
use snell_runtime::{
    ClientConfig, Outbound, ReusePool, ServerConfig, UdpOptions, serve_client, serve_server,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

const PSK: &[u8] = b"0123456789abcdef";
const BULK_BYTES: usize = 16 * 1024 * 1024;
const BULK_CHUNK: usize = 64 * 1024;
const SMALL_SIZE: usize = 64;
const SMALL_ROUNDS: usize = 4_000;
const MID_SIZE: usize = 8 * 1024;
const MID_ROUNDS: usize = 500;
const TCP_CONNS: usize = 4;
const CHURN_CONNS: usize = 16;
const UDP_PING_ROUNDS: usize = 2_000;
const UDP_BURST_ROUNDS: usize = 800;
const UDP_BURST_WINDOW: usize = 8;
const UDP_PAYLOAD: [u8; 64] = [0x5A; 64];

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(run());
}

async fn run() {
    for flavor in [
        ProtocolFlavor::V4,
        ProtocolFlavor::V6Shaped,
        ProtocolFlavor::V6Unshaped,
    ] {
        // Auto only probes v4 and v6-shaped; exercise the probe where possible.
        let selection = match flavor {
            ProtocolFlavor::V4 | ProtocolFlavor::V6Shaped => ProtocolSelection::Auto,
            _ => ProtocolSelection::Exact(flavor),
        };
        let started = Instant::now();

        let pair = start_pair(flavor, selection, None).await;
        concurrent_tcp(pair.socks).await.expect("tcp");
        udp_traffic(pair.socks).await.expect("udp");
        drop(pair);

        let pool = ReusePool::new();
        let pair = start_pair(flavor, selection, Some(pool.clone())).await;
        churn(pair.socks).await.expect("churn");
        drop(pair);

        eprintln!(
            "pgo_train {flavor:?} selection={selection:?} elapsed={:?} pool_len={}",
            started.elapsed(),
            pool.len()
        );
    }
}

struct Pair {
    socks: SocketAddr,
    _stop_client: oneshot::Sender<()>,
    _stop_server: oneshot::Sender<()>,
}

struct Echo {
    addr: SocketAddr,
    join: tokio::task::JoinHandle<io::Result<()>>,
}

async fn start_pair(
    flavor: ProtocolFlavor,
    selection: ProtocolSelection,
    pool: Option<ReusePool>,
) -> Pair {
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = client_listener.local_addr().unwrap();
    let (stop_server, server_rx) = oneshot::channel::<()>();
    let (stop_client, client_rx) = oneshot::channel::<()>();
    let server_cfg = ServerConfig {
        limits: Default::default(),
        listen: server_addr,
        psk: psk.clone(),
        selection,
        outbound: Outbound::Direct,
        udp: UdpOptions::default(),
        tcp_brutal: None,
    };
    tokio::spawn(async move {
        let _ = serve_server(server_listener, server_cfg, async {
            let _ = server_rx.await;
        })
        .await;
    });
    let client_cfg = ClientConfig {
        limits: Default::default(),
        listen: socks,
        server: server_addr,
        psk,
        version: flavor,
        reuse: pool.is_some(),
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

/// Several parallel connections, each mixing a bulk stream with small and
/// mid-size ping-pong so record decode-ahead, batching, and per-record
/// paths all get trained under concurrency.
async fn concurrent_tcp(socks: SocketAddr) -> io::Result<()> {
    let mut tasks = Vec::with_capacity(TCP_CONNS);
    for _ in 0..TCP_CONNS {
        tasks.push(tokio::spawn(async move {
            let echo = spawn_echo().await?;
            let mut stream = socks5_connect(socks, echo.addr).await?;
            stream.set_nodelay(true)?;
            pipelined_echo(&mut stream, BULK_BYTES, BULK_CHUNK, 0xA5).await?;
            ping_pong(&mut stream, &[0x5Au8; SMALL_SIZE], SMALL_ROUNDS).await?;
            ping_pong(&mut stream, &[0xC3u8; MID_SIZE], MID_ROUNDS).await?;
            stream.shutdown().await?;
            echo.join.await.map_err(io::Error::other)??;
            io::Result::Ok(())
        }));
    }
    for task in tasks {
        task.await.map_err(io::Error::other)??;
    }
    Ok(())
}

/// Sequential short-lived connections through the reuse pool: the first
/// dials and runs the KDF, later ones take the pooled Snell connection.
async fn churn(socks: SocketAddr) -> io::Result<()> {
    for i in 0..CHURN_CONNS {
        let echo = spawn_echo().await?;
        let mut stream = socks5_connect(socks, echo.addr).await?;
        let msg = [i as u8; 128];
        stream.write_all(&msg).await?;
        stream.shutdown().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        if buf != msg {
            return Err(io::Error::other("churn echo mismatch"));
        }
        echo.join.await.map_err(io::Error::other)??;
    }
    Ok(())
}

async fn udp_traffic(socks: SocketAddr) -> io::Result<()> {
    let echo = spawn_udp_echo().await?;
    let session = socks5_udp_associate(socks).await?;
    udp_ping_pong(&session, echo, &UDP_PAYLOAD, UDP_PING_ROUNDS).await?;
    udp_burst(
        &session,
        echo,
        &UDP_PAYLOAD,
        UDP_BURST_ROUNDS,
        UDP_BURST_WINDOW,
    )
    .await?;
    Ok(())
}

async fn spawn_echo() -> io::Result<Echo> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let join = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; BULK_CHUNK];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await?;
        }
        io::Result::Ok(())
    });
    Ok(Echo { addr, join })
}

async fn socks5_connect(socks: SocketAddr, dest: SocketAddr) -> io::Result<TcpStream> {
    let mut client = TcpStream::connect(socks).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(io::Error::other("socks5 method negotiation failed"));
    }
    let SocketAddr::V4(dest_v4) = dest else {
        return Err(io::Error::other("echo must be ipv4"));
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&dest_v4.ip().octets());
    request.extend_from_slice(&dest_v4.port().to_be_bytes());
    client.write_all(&request).await?;
    let mut reply_head = [0u8; 4];
    client.read_exact(&mut reply_head).await?;
    if reply_head[0] != 0x05 || reply_head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "socks5 connect failed: {reply_head:?}"
        )));
    }
    let mut bind = [0u8; 6];
    client.read_exact(&mut bind).await?;
    Ok(client)
}

async fn pipelined_echo(
    stream: &mut TcpStream,
    total: usize,
    chunk: usize,
    fill: u8,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.split();
    let send = async {
        let payload = vec![fill; chunk];
        let mut sent = 0usize;
        while sent < total {
            let n = chunk.min(total - sent);
            writer.write_all(&payload[..n]).await?;
            sent += n;
        }
        io::Result::Ok(())
    };
    let recv = async {
        let mut buf = vec![0u8; chunk];
        let mut recvd = 0usize;
        while recvd < total {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "bulk stream eof",
                ));
            }
            if buf[..n].iter().any(|byte| *byte != fill) {
                return Err(io::Error::other("bulk stream echo mismatch"));
            }
            recvd += n;
        }
        io::Result::Ok(())
    };
    tokio::try_join!(send, recv)?;
    Ok(())
}

async fn ping_pong(stream: &mut TcpStream, msg: &[u8], rounds: usize) -> io::Result<()> {
    let mut echoed = vec![0u8; msg.len()];
    for _ in 0..rounds {
        stream.write_all(msg).await?;
        stream.read_exact(&mut echoed).await?;
        if echoed != msg {
            return Err(io::Error::other("ping-pong echo mismatch"));
        }
    }
    Ok(())
}

struct UdpSession {
    _tcp: TcpStream,
    relay: SocketAddr,
    client: UdpSocket,
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

async fn socks5_udp_associate(socks: SocketAddr) -> io::Result<UdpSession> {
    let mut tcp = TcpStream::connect(socks).await?;
    tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    tcp.read_exact(&mut method).await?;
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut reply_head = [0u8; 4];
    tcp.read_exact(&mut reply_head).await?;
    let mut rest = [0u8; 6];
    tcp.read_exact(&mut rest).await?;
    let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
    let port = u16::from_be_bytes([rest[4], rest[5]]);
    let relay = SocketAddr::from((ip, port));
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    Ok(UdpSession {
        _tcp: tcp,
        relay,
        client,
    })
}

async fn udp_ping_pong(
    session: &UdpSession,
    echo: SocketAddr,
    payload: &[u8],
    rounds: usize,
) -> io::Result<()> {
    let mut packet = vec![0u8; 32 + payload.len()];
    let n = socks5::encode_udp_packet(&mut packet, 0, AddressRef::Ip(echo), payload)
        .map_err(io::Error::other)?;
    packet.truncate(n);
    let mut buf = [0u8; 2048];
    for _ in 0..rounds {
        session.client.send_to(&packet, session.relay).await?;
        let (got, _) = session.client.recv_from(&mut buf).await?;
        let parsed = socks5::parse_udp_packet(&buf[..got]).map_err(io::Error::other)?;
        if parsed.payload != payload {
            return Err(io::Error::other("udp payload mismatch"));
        }
    }
    Ok(())
}

async fn udp_burst(
    session: &UdpSession,
    echo: SocketAddr,
    payload: &[u8],
    rounds: usize,
    window: usize,
) -> io::Result<()> {
    let mut packet = vec![0u8; 32 + payload.len()];
    let n = socks5::encode_udp_packet(&mut packet, 0, AddressRef::Ip(echo), payload)
        .map_err(io::Error::other)?;
    packet.truncate(n);
    let mut buf = [0u8; 2048];
    for _ in 0..rounds {
        for _ in 0..window {
            session.client.send_to(&packet, session.relay).await?;
        }
        for _ in 0..window {
            let recv = session.client.recv_from(&mut buf);
            let (got, _) = tokio::time::timeout(std::time::Duration::from_secs(5), recv)
                .await
                .map_err(|_| io::Error::other("udp burst response timed out"))??;
            let parsed = socks5::parse_udp_packet(&buf[..got]).map_err(io::Error::other)?;
            if parsed.payload != payload {
                return Err(io::Error::other("udp payload mismatch"));
            }
        }
    }
    Ok(())
}

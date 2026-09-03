//! UDP loopback on an established SOCKS5 UDP association.
//!
//! Handshake/KDF is warmed up and excluded from the timed window.
//! Workload is ping-pong datagrams on the same association.
//!
//! Run: `cargo bench -p snell-runtime --bench udp_loopback`

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use snell_protocol::socks5;
use snell_protocol::{AddressRef, ProtocolFlavor, ProtocolSelection, Psk};
use snell_runtime::{ClientConfig, Outbound, ServerConfig, UdpOptions, serve_client, serve_server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

const PSK: &[u8] = b"0123456789abcdef";
const WARMUP_ROUNDS: usize = 100;
const PING_ROUNDS: usize = 5_000;
const PAYLOAD: [u8; 64] = [0x5A; 64];

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(run());
}

async fn run() {
    let pair = start_pair().await;
    let echo = spawn_udp_echo().await.expect("echo");
    let handshake_started = Instant::now();
    let session = socks5_udp_associate(pair.socks).await.expect("associate");
    let handshake_elapsed = handshake_started.elapsed();

    ping_pong(&session, echo, &PAYLOAD, WARMUP_ROUNDS)
        .await
        .expect("warmup");

    let ping_started = Instant::now();
    ping_pong(&session, echo, &PAYLOAD, PING_ROUNDS)
        .await
        .expect("ping");
    let ping_elapsed = ping_started.elapsed();

    eprintln!(
        "v4 udp loopback established association, handshake excluded from ping-pong\n\
         handshake: elapsed={handshake_elapsed:?}\n\
         ping: rounds={PING_ROUNDS} size={} elapsed={ping_elapsed:?}",
        PAYLOAD.len()
    );
}

struct Pair {
    socks: SocketAddr,
    _stop_client: oneshot::Sender<()>,
    _stop_server: oneshot::Sender<()>,
}

struct UdpSession {
    _tcp: TcpStream,
    relay: SocketAddr,
    client: UdpSocket,
}

async fn start_pair() -> Pair {
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = client_listener.local_addr().unwrap();
    let (stop_server, server_rx) = oneshot::channel::<()>();
    let (stop_client, client_rx) = oneshot::channel::<()>();
    let server_cfg = ServerConfig {
        listen: server_addr,
        psk: psk.clone(),
        selection: ProtocolSelection::Exact(ProtocolFlavor::V4),
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
        listen: socks,
        server: server_addr,
        psk,
        version: ProtocolFlavor::V4,
        reuse: false,
        pool: None,
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

async fn ping_pong(
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

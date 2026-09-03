//! TCP one-shot loopback on established v4 and v6 sessions.
//!
//! Handshake/KDF is warmed up and excluded from the timed window.
//! Large stream is pipelined echo (write and read concurrently).
//! Small messages are ping-pong on the same connection.
//!
//! Run: `cargo bench -p snell-runtime --bench tcp_loopback`

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use snell_protocol::{ProtocolFlavor, ProtocolSelection, Psk};
use snell_runtime::{ClientConfig, Outbound, ServerConfig, UdpOptions, serve_client, serve_server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const PSK: &[u8] = b"0123456789abcdef";
const WARMUP_BYTES: usize = 64 * 1024;
const LARGE_BYTES: usize = 32 * 1024 * 1024;
const LARGE_CHUNK: usize = 64 * 1024;
const SMALL_SIZE: usize = 64;
const SMALL_ROUNDS: usize = 20_000;

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
        let pair = start_pair(flavor).await;
        let echo = spawn_echo().await.expect("echo");
        let handshake_started = Instant::now();
        let mut stream = socks5_connect(pair.socks, echo.addr)
            .await
            .expect("socks5 connect");
        stream.set_nodelay(true).expect("nodelay");
        let handshake_elapsed = handshake_started.elapsed();

        let warmup = vec![0xA5u8; WARMUP_BYTES];
        sequential_echo(&mut stream, &warmup).await.expect("warmup");

        let large_started = Instant::now();
        pipelined_echo(&mut stream, LARGE_BYTES, LARGE_CHUNK, 0xA5)
            .await
            .expect("large");
        let large_elapsed = large_started.elapsed();

        let small = [0x5Au8; SMALL_SIZE];
        let small_started = Instant::now();
        ping_pong(&mut stream, &small, SMALL_ROUNDS)
            .await
            .expect("small");
        let small_elapsed = small_started.elapsed();

        stream.shutdown().await.expect("shutdown");
        echo.join.await.expect("echo join").expect("echo copy");

        eprintln!(
            "{flavor:?} tcp loopback established session, handshake excluded from large/small\n\
             handshake: elapsed={handshake_elapsed:?}\n\
             large: bytes={LARGE_BYTES} chunk={LARGE_CHUNK} elapsed={large_elapsed:?}\n\
             small: rounds={SMALL_ROUNDS} size={SMALL_SIZE} elapsed={small_elapsed:?}"
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

async fn start_pair(flavor: ProtocolFlavor) -> Pair {
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
        selection: ProtocolSelection::Exact(flavor),
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
        version: flavor,
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

async fn spawn_echo() -> io::Result<Echo> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let join = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; LARGE_CHUNK];
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

async fn sequential_echo(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await?;
    if echoed != payload {
        return Err(io::Error::other("warmup echo mismatch"));
    }
    Ok(())
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
                    "large stream eof",
                ));
            }
            if buf[..n].iter().any(|byte| *byte != fill) {
                return Err(io::Error::other("large stream echo mismatch"));
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
            return Err(io::Error::other("small message echo mismatch"));
        }
    }
    Ok(())
}

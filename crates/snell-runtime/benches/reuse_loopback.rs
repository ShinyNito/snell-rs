//! Two SOCKS5 echoes on reused Snell v4 and v6 connections.
//!
//! Run: `cargo bench -p snell-runtime --bench reuse_loopback`

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use snell_protocol::{ProtocolFlavor, ProtocolSelection, Psk};
use snell_runtime::{
    ClientConfig, Outbound, ReusePool, ServerConfig, UdpOptions, serve_client, serve_server,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const PSK: &[u8] = b"0123456789abcdef";

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
        let pool = ReusePool::new();
        let pair = start_pair(flavor, pool.clone()).await;
        let echo = spawn_echo().await.expect("echo1");
        let started = Instant::now();
        let mut stream = socks5_connect(pair.socks, echo.addr).await.expect("c1");
        stream.write_all(b"one").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"one");
        echo.join.await.unwrap().unwrap();
        let first = started.elapsed();

        let echo = spawn_echo().await.expect("echo2");
        let started = Instant::now();
        let mut stream = socks5_connect(pair.socks, echo.addr).await.expect("c2");
        stream.write_all(b"two").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"two");
        echo.join.await.unwrap().unwrap();
        let second = started.elapsed();

        eprintln!(
            "{flavor:?} reuse two SOCKS5 echoes\n\
             first (dial+kdf): elapsed={first:?}\n\
             second (pooled): elapsed={second:?}\n\
             pool_len={}",
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

async fn start_pair(flavor: ProtocolFlavor, pool: ReusePool) -> Pair {
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
        reuse: true,
        pool: Some(pool),
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
        let mut buf = vec![0u8; 4096];
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

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use snell_testkit::oracle::{ClientOptions, ProcessPair, SnellBinary};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const PSK: &str = "0123456789abcdef";

fn workspace_bin() -> SnellBinary {
    SnellBinary::from_path(env!("CARGO_BIN_EXE_snell-rs")).expect("workspace snell-rs binary")
}

async fn spawn_udp_echo() -> std::io::Result<SocketAddr> {
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

fn socks5_udp_ipv4(dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::SocketAddr::V4(v4) = dest else {
        panic!("ipv4 dest");
    };
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&v4.ip().octets());
    packet.extend_from_slice(&v4.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn socks5_udp_echo(socks: SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let echo = spawn_udp_echo().await?;
    let mut tcp = TcpStream::connect(socks).await?;
    tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    tcp.read_exact(&mut method).await?;
    assert_eq!(method, [0x05, 0x00]);
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut reply_head = [0u8; 4];
    tcp.read_exact(&mut reply_head).await?;
    assert_eq!(reply_head, [0x05, 0x00, 0x00, 0x01]);
    let mut rest = [0u8; 6];
    tcp.read_exact(&mut rest).await?;
    let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
    let port = u16::from_be_bytes([rest[4], rest[5]]);
    let relay = SocketAddr::from((ip, port));
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let packet = socks5_udp_ipv4(echo, payload);
    client.send_to(&packet, relay).await?;
    let mut buf = [0u8; 65535];
    let (n, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "udp echo timed out"))??;
    assert!(n >= 10);
    assert_eq!(&buf[..3], &[0, 0, 0]);
    Ok(buf[10..n].to_vec())
}

#[tokio::test]
async fn new_v4_udp_echo() {
    let pair = ProcessPair::spawn(
        &workspace_bin(),
        PSK,
        Some("4"),
        ClientOptions {
            version: "v4",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"new-new-v4-udp";
    let echoed = socks5_udp_echo(pair.socks, payload).await.expect("echo");
    assert_eq!(echoed, payload);
}

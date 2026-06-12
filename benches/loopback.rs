use std::hint::black_box;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use snell_rs::service::runtime::client::bind_configured_socks5_client_with_shutdown;
use snell_rs::service::runtime::config::{ClientConfig, ServerConfig};
use snell_rs::service::runtime::server::bind_configured_tcp_server_with_shutdown;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const PSK: &[u8] = b"benchmark psk";
const PAYLOAD_SIZES: [usize; 3] = [16 * 1024, 256 * 1024, 1024 * 1024];

fn benchmark_loopback_tcp(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let no_reuse = runtime.block_on(LoopbackHarness::start(false)).unwrap();
    let reuse = runtime.block_on(LoopbackHarness::start(true)).unwrap();

    let mut group = c.benchmark_group("loopback/tcp_echo");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    for (mode, harness) in [("reuse_off", &no_reuse), ("reuse_on", &reuse)] {
        for size in PAYLOAD_SIZES {
            let payload = Arc::new(vec![0x42; size]);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
                let payload = payload.clone();
                b.to_async(&runtime).iter(|| {
                    let payload = payload.clone();
                    async move {
                        let received =
                            transfer_once(harness.socks_addr, harness.echo_addr, &payload)
                                .await
                                .unwrap();
                        black_box(received);
                    }
                });
            });
        }
    }

    group.finish();
    no_reuse.shutdown();
    reuse.shutdown();
    runtime.block_on(async {
        sleep(Duration::from_millis(50)).await;
    });
}

struct LoopbackHarness {
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    shutdowns: Vec<CancellationToken>,
    _tasks: Vec<JoinHandle<()>>,
}

impl LoopbackHarness {
    async fn start(reuse: bool) -> io::Result<Self> {
        let echo_listener = TcpListener::bind(loopback_addr(0)).await?;
        let echo_addr = echo_listener.local_addr()?;
        let echo_shutdown = CancellationToken::new();
        let echo_task = spawn_echo_server(echo_listener, echo_shutdown.clone());

        let snell_addr = available_loopback_addr()?;
        let snell_shutdown = CancellationToken::new();
        let snell_config = ServerConfig {
            listen: vec![snell_addr],
            psk: Zeroizing::new(PSK.to_vec()),
            version: snell_rs::VERSION_4,
            ipv6: false,
            dns: None,
            dns_ip_preference: Default::default(),
            tcp_fast_open: false,
            quic_proxy: false,
            tcp_brutal: None,
            upstream_socks5: None,
        };
        let snell_task = spawn_snell_server(snell_config, snell_shutdown.clone());
        wait_for_tcp(snell_addr).await?;

        let socks_addr = available_loopback_addr()?;
        let socks_shutdown = CancellationToken::new();
        let client_config = ClientConfig {
            listen: socks_addr,
            server: snell_addr,
            psk: Zeroizing::new(PSK.to_vec()),
            version: snell_rs::VERSION_4,
            reuse,
            quic_proxy: false,
        };
        let socks_task = spawn_socks5_client(client_config, socks_shutdown.clone());
        wait_for_tcp(socks_addr).await?;

        Ok(Self {
            socks_addr,
            echo_addr,
            shutdowns: vec![echo_shutdown, snell_shutdown, socks_shutdown],
            _tasks: vec![echo_task, snell_task, socks_task],
        })
    }

    fn shutdown(&self) {
        for shutdown in &self.shutdowns {
            shutdown.cancel();
        }
    }
}

fn spawn_echo_server(listener: TcpListener, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        if !shutdown.is_cancelled() {
                            panic!("echo server accept failed");
                        }
                        break;
                    };
                    tokio::spawn(async move {
                        if let Err(err) = echo_connection(stream).await
                            && !is_closed_io_kind(err.kind())
                        {
                            panic!("echo connection failed: {err}");
                        }
                    });
                }
            }
        }
    })
}

async fn echo_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut len = [0; 8];
    stream.read_exact(&mut len).await?;
    let mut remaining = u64::from_be_bytes(len) as usize;
    let mut buf = vec![0; 64 * 1024];
    while remaining != 0 {
        let chunk_len = remaining.min(buf.len());
        let n = stream.read(&mut buf[..chunk_len]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("echo received {} bytes less than expected", remaining),
            ));
        }
        stream.write_all(&buf[..n]).await?;
        remaining -= n;
    }
    stream.shutdown().await
}

fn spawn_snell_server(config: ServerConfig, shutdown: CancellationToken) -> JoinHandle<()> {
    let task_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let result = bind_configured_tcp_server_with_shutdown(config, task_shutdown.clone()).await;
        if let Err(err) = result
            && !task_shutdown.is_cancelled()
        {
            panic!("snell server failed: {err}");
        }
    })
}

fn spawn_socks5_client(config: ClientConfig, shutdown: CancellationToken) -> JoinHandle<()> {
    let task_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let result =
            bind_configured_socks5_client_with_shutdown(config, task_shutdown.clone()).await;
        if let Err(err) = result
            && !task_shutdown.is_cancelled()
        {
            panic!("socks5 client failed: {err}");
        }
    })
}

async fn transfer_once(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.set_nodelay(true)?;
    write_socks5_connect(&mut stream, target_addr).await?;

    stream
        .write_all(&(payload.len() as u64).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;

    let mut received = 0;
    let mut buf = vec![0; 64 * 1024];
    while received < payload.len() {
        let n = stream.read(&mut buf).await.map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "read response failed after receiving {received} of {} bytes: {err}",
                    payload.len()
                ),
            )
        })?;
        if n == 0 {
            break;
        }
        received += n;
    }

    if received != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("received {received} of {} bytes", payload.len()),
        ));
    }
    Ok(received)
}

async fn write_socks5_connect(stream: &mut TcpStream, target_addr: SocketAddr) -> io::Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected method selection {method:?}"),
        ));
    }

    let IpAddr::V4(target_ip) = target_addr.ip() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "loopback benchmark only supports IPv4 targets",
        ));
    };

    let mut request = Vec::with_capacity(10);
    request.extend_from_slice(&[5, 1, 0, 1]);
    request.extend_from_slice(&target_ip.octets());
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5 connect failed with reply {reply:?}"),
        ));
    }
    Ok(())
}

fn is_closed_io_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    )
}

async fn wait_for_tcp(addr: SocketAddr) -> io::Result<()> {
    let mut last_error = None;
    for _ in 0..100 {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(err) => {
                last_error = Some(err);
                sleep(Duration::from_millis(10)).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out waiting for {addr}"),
        )
    }))
}

fn available_loopback_addr() -> io::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind(loopback_addr(0))?;
    listener.local_addr()
}

fn loopback_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn criterion_config() -> Criterion {
    Criterion::default()
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = benchmark_loopback_tcp
}
criterion_main!(benches);

use std::hint::black_box;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use snell_rs::client::bind_configured_socks5_client_with_shutdown;
use snell_rs::config::{ClientConfig, ServerConfig};
use snell_rs::server::bind_configured_tcp_server_with_shutdown;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const PSK: &[u8] = b"benchmark psk";
const PAYLOAD_SIZES: [usize; 2] = [64, 1200];
const BATCH: usize = 16;
const SOCKS_UDP_IPV4_HEADER: usize = 3 + 1 + 4 + 2;
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

fn benchmark_loopback_udp(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let harness = runtime.block_on(UdpLoopbackHarness::start()).unwrap();
    let association = Arc::new(runtime.block_on(harness.open_association()).unwrap());

    let mut group = c.benchmark_group("loopback/udp_echo");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    for size in PAYLOAD_SIZES {
        let payload = Arc::new(vec![0x42; size]);
        group.throughput(Throughput::Bytes((size * BATCH) as u64));
        group.bench_with_input(BenchmarkId::new("batch16", size), &size, |b, _| {
            let payload = payload.clone();
            let association = association.clone();
            let echo_addr = harness.echo_addr;
            b.to_async(&runtime).iter(move || {
                let payload = payload.clone();
                let association = association.clone();
                async move {
                    let received = association.echo_batch(&payload, echo_addr).await.unwrap();
                    black_box(received);
                }
            });
        });
    }

    group.finish();
    drop(association);
    harness.shutdown();
    runtime.block_on(async {
        sleep(Duration::from_millis(50)).await;
    });
}

struct UdpLoopbackHarness {
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    shutdowns: Vec<CancellationToken>,
    _tasks: Vec<JoinHandle<()>>,
}

impl UdpLoopbackHarness {
    async fn start() -> io::Result<Self> {
        let echo_socket = UdpSocket::bind(loopback_addr(0)).await?;
        let echo_addr = echo_socket.local_addr()?;
        let echo_shutdown = CancellationToken::new();
        let echo_task = spawn_udp_echo_server(echo_socket, echo_shutdown.clone());

        let snell_addr = available_loopback_addr()?;
        let snell_shutdown = CancellationToken::new();
        let snell_config = ServerConfig {
            listen: vec![snell_addr],
            psk: Zeroizing::new(PSK.to_vec()),
            ipv6: false,
            dns: None,
            dns_ip_preference: Default::default(),
            tcp_fast_open: false,
            quic_proxy: false,
            tcp_brutal: None,
            upstream_socks5: None,
        };
        let snell_task = spawn_snell_server(snell_config, &snell_shutdown);
        wait_for_tcp(snell_addr).await?;

        let socks_addr = available_loopback_addr()?;
        let socks_shutdown = CancellationToken::new();
        let client_config = ClientConfig {
            listen: socks_addr,
            server: snell_addr,
            psk: Zeroizing::new(PSK.to_vec()),
            version: snell_rs::ProtocolVersion::V4,
            reuse: false,
            quic_proxy: false,
        };
        let socks_task = spawn_socks5_client(client_config, &socks_shutdown);
        wait_for_tcp(socks_addr).await?;

        Ok(Self {
            socks_addr,
            echo_addr,
            shutdowns: vec![echo_shutdown, snell_shutdown, socks_shutdown],
            _tasks: vec![echo_task, snell_task, socks_task],
        })
    }

    async fn open_association(&self) -> io::Result<UdpAssociation> {
        let mut control = TcpStream::connect(self.socks_addr).await?;
        control.set_nodelay(true)?;
        control.write_all(&[5, 1, 0]).await?;
        let mut method = [0; 2];
        control.read_exact(&mut method).await?;
        if method != [5, 0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected method selection {method:?}"),
            ));
        }

        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await?;
        if reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("socks5 udp associate failed with reply {reply:?}"),
            ));
        }
        let bind_ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
        let bind_ip = if bind_ip.is_unspecified() {
            match self.socks_addr.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "udp benchmark only supports IPv4",
                    ));
                }
            }
        } else {
            bind_ip
        };
        let relay_addr = SocketAddr::new(
            IpAddr::V4(bind_ip),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let socket = UdpSocket::bind(loopback_addr(0)).await?;

        Ok(UdpAssociation {
            _control: control,
            socket,
            relay_addr,
        })
    }

    fn shutdown(&self) {
        for shutdown in &self.shutdowns {
            shutdown.cancel();
        }
    }
}

struct UdpAssociation {
    _control: TcpStream,
    socket: UdpSocket,
    relay_addr: SocketAddr,
}

impl UdpAssociation {
    async fn echo_batch(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        let IpAddr::V4(target_ip) = target.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "udp benchmark only supports IPv4 targets",
            ));
        };
        let mut request = Vec::with_capacity(SOCKS_UDP_IPV4_HEADER + payload.len());
        request.extend_from_slice(&[0, 0, 0, 1]);
        request.extend_from_slice(&target_ip.octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        request.extend_from_slice(payload);

        for _ in 0..BATCH {
            self.socket.send_to(&request, self.relay_addr).await?;
        }

        let mut buf = vec![0; SOCKS_UDP_IPV4_HEADER + payload.len() + 64];
        let mut received = 0;
        for _ in 0..BATCH {
            let (n, _) = timeout(RECV_TIMEOUT, self.socket.recv_from(&mut buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "udp echo timed out"))??;
            received += n.saturating_sub(SOCKS_UDP_IPV4_HEADER);
        }
        Ok(received)
    }
}

fn spawn_udp_echo_server(socket: UdpSocket, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0; 64 * 1024];
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                result = socket.recv_from(&mut buf) => {
                    let Ok((n, peer)) = result else {
                        if !shutdown.is_cancelled() {
                            panic!("udp echo server recv failed");
                        }
                        break;
                    };
                    if socket.send_to(&buf[..n], peer).await.is_err() && !shutdown.is_cancelled() {
                        panic!("udp echo server send failed");
                    }
                }
            }
        }
    })
}

fn spawn_snell_server(config: ServerConfig, shutdown: &CancellationToken) -> JoinHandle<()> {
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

fn spawn_socks5_client(config: ClientConfig, shutdown: &CancellationToken) -> JoinHandle<()> {
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
    targets = benchmark_loopback_udp
}
criterion_main!(benches);

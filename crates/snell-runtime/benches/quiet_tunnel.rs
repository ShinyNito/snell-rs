//! Persistent tunnels: 100/256 connections, five 2 MiB echo/5 s quiet/resume rounds.
//! Driver, echo, client and server run in separate processes; RSS is sampled with ps.
use snell_protocol::{ProtocolFlavor, ProtocolSelection, Psk};
use snell_runtime::{
    BufferPool, ClientConfig, Outbound, ServerConfig, UdpOptions, serve_client, serve_server,
};
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
const PSK: &[u8] = b"0123456789abcdef";

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            if args.first().is_some_and(|a| a.starts_with("--role=")) {
                role(&args).await
            } else {
                run().await
            }
        })
        .unwrap();
}

async fn role(args: &[String]) -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen = listener.local_addr()?;
    println!("{listen}");
    io::stdout().flush()?;
    if args[0] == "--role=echo" {
        // Exactly the driver's bounded connection count, one task per open stream.
        let count: usize = args[1].parse().unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..count {
            let (stream, _) = listener.accept().await?;
            tasks.spawn(async move {
                let (mut r, mut w) = stream.into_split();
                tokio::io::copy(&mut r, &mut w).await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result??;
        }
        return Ok(());
    }
    let flavor = match args[1].as_str() {
        "v4" => ProtocolFlavor::V4,
        "v6s" => ProtocolFlavor::V6Shaped,
        "v6u" => ProtocolFlavor::V6Unshaped,
        _ => panic!("unknown benchmark flavor"),
    };
    let buffers = Arc::new(BufferPool::default());
    let stats = Arc::clone(&buffers);
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            assert_eq!(line.unwrap(), "stats");
            let s = stats.stats();
            println!(
                "{} {} {} {} {} {}",
                s.allocated_bytes, s.leased_bytes, s.cached_bytes, s.hits, s.misses, s.rejected
            );
            io::stdout().flush().unwrap();
        }
    });
    let psk = Psk::new(PSK).unwrap();
    let result = if args[0] == "--role=server" {
        serve_server(
            listener,
            ServerConfig {
                listen,
                psk,
                selection: ProtocolSelection::Exact(flavor),
                outbound: Outbound::Direct,
                buffers,
                udp: UdpOptions::default(),
                tcp_brutal: None,
            },
            std::future::pending(),
        )
        .await
    } else {
        serve_client(
            listener,
            ClientConfig {
                listen,
                server: args[2].parse().unwrap(),
                psk,
                version: flavor,
                reuse: false,
                pool: None,
                buffers,
                udp: UdpOptions::default(),
            },
            std::future::pending(),
        )
        .await
    };
    result.map_err(io::Error::other)
}

struct Process {
    child: Child,
    output: io::BufReader<std::process::ChildStdout>,
    addr: SocketAddr,
}
impl Process {
    fn start(args: &[&str]) -> io::Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut output = io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line)?;
        let addr = line.trim().parse().map_err(io::Error::other)?;
        Ok(Self {
            child,
            output,
            addr,
        })
    }
    fn sample(
        &mut self,
        flavor: &str,
        count: usize,
        round: usize,
        phase: &str,
        role: &str,
    ) -> io::Result<()> {
        writeln!(self.child.stdin.as_mut().unwrap(), "stats")?;
        let mut line = String::new();
        self.output.read_line(&mut line)?;
        let values: Vec<u64> = line
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 6);
        let rss = Command::new("ps")
            .args(["-o", "rss=", "-p", &self.child.id().to_string()])
            .output()?;
        assert!(rss.status.success());
        let rss: u64 = String::from_utf8(rss.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        println!(
            "{flavor},{count},{round},{phase},{role},{rss},{},{},{},{},{},{}",
            values[0], values[1], values[2], values[3], values[4], values[5]
        );
        io::stdout().flush()?;
        assert_eq!(values[5], 0, "no budget rejection");
        if phase == "quiet" {
            assert_eq!(
                values[1], 0,
                "open quiet tunnels must return working storage"
            );
        }
        Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn traffic(streams: Vec<TcpStream>, bulk: bool, fill: u8) -> io::Result<Vec<TcpStream>> {
    let mut tasks = tokio::task::JoinSet::new();
    for (index, mut stream) in streams.into_iter().enumerate() {
        tasks.spawn(async move {
            if bulk {
                // Bound each driver's outstanding echo window to 64 KiB so the
                // loopback kernel does not queue 2 MiB per socket at once.
                // Every connection still transfers 2 MiB in each direction.
                for _ in 0..32 {
                    pipelined_echo(&mut stream, 64 << 10, 8 << 10, fill)
                        .await
                        .map_err(|e| io::Error::other(format!("connection {index} bulk: {e}")))?;
                }
            } else {
                sequential_echo(&mut stream, &[fill; 64]).await?;
            }
            io::Result::Ok((index, stream))
        });
    }
    let mut returned = Vec::with_capacity(tasks.len());
    while let Some(result) = tasks.join_next().await {
        returned.push(result??);
    }
    returned.sort_unstable_by_key(|(i, _)| *i);
    Ok(returned.into_iter().map(|(_, s)| s).collect())
}

async fn run() -> io::Result<()> {
    println!(
        "flavor,connections,round,phase,role,rss_kib,allocated,leased,cached,hits,misses,rejected"
    );
    for flavor in ["v4", "v6s", "v6u"] {
        for count in [100, 256] {
            let echo = Process::start(&["--role=echo", &count.to_string()])?;
            let mut server = Process::start(&["--role=server", flavor])?;
            let mut client = Process::start(&["--role=client", flavor, &server.addr.to_string()])?;
            let mut streams = Vec::with_capacity(count);
            for _ in 0..count {
                let s = socks5_connect(client.addr, echo.addr).await?;
                s.set_nodelay(true)?;
                streams.push(s);
            }
            streams = traffic(streams, false, 0x11).await?;
            for round in 1..=5 {
                for phase in ["before", "bulk", "quiet", "resume"] {
                    match phase {
                        "bulk" => {
                            let start = Instant::now();
                            streams = traffic(streams, true, round as u8).await?;
                            eprintln!(
                                "{flavor} n={count} round={round} bulk_ms={:.3}",
                                start.elapsed().as_secs_f64() * 1000.0
                            );
                        }
                        "quiet" => tokio::time::sleep(Duration::from_secs(5)).await,
                        "resume" => {
                            let start = Instant::now();
                            streams = traffic(streams, false, 0x80 + round as u8).await?;
                            eprintln!(
                                "{flavor} n={count} round={round} all_resume_ms={:.3}",
                                start.elapsed().as_secs_f64() * 1000.0
                            );
                        }
                        _ => {}
                    }
                    server.sample(flavor, count, round, phase, "server")?;
                    client.sample(flavor, count, round, phase, "client")?;
                }
            }
            // The same sockets survive all five rounds; shutdown happens only here.
            for mut stream in streams {
                stream.shutdown().await?;
            }
        }
    }
    Ok(())
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
            writer
                .write_all(&payload[..n])
                .await
                .map_err(|e| io::Error::other(format!("driver send after {sent} bytes: {e}")))?;
            sent += n;
        }
        io::Result::Ok(())
    };
    let recv = async {
        let mut buf = vec![0u8; chunk];
        let mut recvd = 0usize;
        while recvd < total {
            let n = reader.read(&mut buf).await.map_err(|e| {
                io::Error::other(format!("driver receive after {recvd} bytes: {e}"))
            })?;
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

//! Worker processes and echo traffic for the staggered tunnel benchmark.
use snell_protocol::{ProtocolFlavor, ProtocolSelection, Psk};
use snell_runtime::{
    BufferPool, ClientConfig, Outbound, ServerConfig, UdpOptions, serve_client, serve_server,
};
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
const PSK: &[u8] = b"0123456789abcdef";

pub(crate) fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(role(&args))
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
            println!("{}", stats.leased_bytes());
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

pub(crate) struct Process {
    child: Child,
    output: io::BufReader<std::process::ChildStdout>,
    pub(crate) addr: SocketAddr,
}
impl Process {
    pub(crate) fn start(args: &[&str]) -> io::Result<Self> {
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
    pub(crate) fn snapshot(&mut self) -> io::Result<(u64, u64)> {
        writeln!(self.child.stdin.as_mut().unwrap(), "stats")?;
        let mut line = String::new();
        self.output.read_line(&mut line)?;
        let leased = line.trim().parse().map_err(io::Error::other)?;
        let rss = Command::new("ps")
            .args(["-o", "rss=", "-p", &self.child.id().to_string()])
            .output()?;
        assert!(rss.status.success());
        let rss: u64 = String::from_utf8(rss.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        Ok((rss, leased))
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) async fn socks5_connect(socks: SocketAddr, dest: SocketAddr) -> io::Result<TcpStream> {
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

pub(crate) async fn pipelined_echo(
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

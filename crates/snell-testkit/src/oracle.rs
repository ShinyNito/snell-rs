//! Spawn a Snell client/server pair as independent processes.
//!
//! The binary is located via `SNELL_RS_TEST_BIN`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use snell_protocol::socks5::{self, Command, Reply};
use snell_protocol::{AddressRef, MAX_UDP_PACKET_ADDR_LEN, ParseState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::{self, Child};
use tokio::time::{sleep, timeout};

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL: Duration = Duration::from_millis(20);

#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    #[error("SNELL_RS_TEST_BIN is not set")]
    MissingBinary,
    #[error("binary not found: {0}")]
    BinaryNotFound(PathBuf),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("process exited early ({role}): {status}")]
    ExitedEarly { role: &'static str, status: String },
    #[error("timed out waiting for {0} to listen")]
    ReadyTimeout(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnellBinary {
    path: PathBuf,
}

impl SnellBinary {
    pub fn from_env() -> Result<Self, OracleError> {
        let path = std::env::var_os("SNELL_RS_TEST_BIN")
            .map(PathBuf::from)
            .ok_or(OracleError::MissingBinary)?;
        Self::from_path(path)
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, OracleError> {
        let path = path.into();
        if !path.is_file() {
            return Err(OracleError::BinaryNotFound(path));
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientOptions {
    pub version: &'static str,
    pub reuse: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            version: "v4",
            reuse: false,
        }
    }
}

/// Server `version` and `mode` keys; the default omits both (auto-detect).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerOptions {
    pub version: Option<&'static str>,
    pub mode: Option<&'static str>,
}

pub struct ProcessPair {
    _dir: tempfile_dir::TempDir,
    _server: Child,
    _client: Child,
    pub socks: SocketAddr,
    pub snell: SocketAddr,
}

impl ProcessPair {
    pub async fn spawn(
        binary: &SnellBinary,
        psk: &str,
        server: ServerOptions,
        client: ClientOptions,
    ) -> Result<Self, OracleError> {
        Self::spawn_binaries(binary, binary, psk, server, client).await
    }

    /// Server and client from different binaries, for differential runs.
    pub async fn spawn_binaries(
        server_bin: &SnellBinary,
        client_bin: &SnellBinary,
        psk: &str,
        server: ServerOptions,
        client: ClientOptions,
    ) -> Result<Self, OracleError> {
        let mut last_error = None;
        for _ in 0..8 {
            match spawn_once(server_bin, client_bin, psk, server, client).await {
                Ok(pair) => return Ok(pair),
                Err(error @ (OracleError::ExitedEarly { .. } | OracleError::ReadyTimeout(_))) => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.expect("spawn retried"))
    }
}

async fn spawn_once(
    server_bin: &SnellBinary,
    client_bin: &SnellBinary,
    psk: &str,
    server_options: ServerOptions,
    client: ClientOptions,
) -> Result<ProcessPair, OracleError> {
    let dir = tempfile_dir::TempDir::new()?;
    let snell = free_listen_addr().await?;
    let socks = free_listen_addr().await?;

    let server_conf = dir.path().join("snell-server.conf");
    let client_conf = dir.path().join("snell-client.conf");
    std::fs::write(&server_conf, server_ini(snell, psk, server_options))?;
    std::fs::write(&client_conf, client_ini(socks, snell, psk, client))?;

    let mut server = spawn_role(server_bin, "server", &server_conf)?;
    wait_listening(&mut server, snell, "server").await?;

    let mut client_proc = spawn_role(client_bin, "client", &client_conf)?;
    wait_listening(&mut client_proc, socks, "client").await?;

    Ok(ProcessPair {
        _dir: dir,
        _server: server,
        _client: client_proc,
        socks,
        snell,
    })
}

fn spawn_role(binary: &SnellBinary, role: &str, config: &Path) -> Result<Child, OracleError> {
    Ok(process::Command::new(binary.path())
        .arg(role)
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?)
}

async fn free_listen_addr() -> Result<SocketAddr, OracleError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn server_ini(listen: SocketAddr, psk: &str, options: ServerOptions) -> String {
    let mut ini = format!("[snell-server]\nlisten = {listen}\npsk = {psk}\n");
    for (key, value) in [("version", options.version), ("mode", options.mode)] {
        if let Some(value) = value {
            ini.push_str(&format!("{key} = {value}\n"));
        }
    }
    ini
}

fn client_ini(listen: SocketAddr, server: SocketAddr, psk: &str, options: ClientOptions) -> String {
    let reuse = if options.reuse { "true" } else { "false" };
    format!(
        "[snell-client]\nlisten = {listen}\nserver = {server}\npsk = {psk}\nversion = {}\nreuse = {reuse}\n",
        options.version
    )
}

async fn wait_listening(
    child: &mut Child,
    addr: SocketAddr,
    role: &'static str,
) -> Result<(), OracleError> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr).await;
            }
            return Err(OracleError::ExitedEarly {
                role,
                status: format!("{status}: {stderr}"),
            });
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(OracleError::ReadyTimeout(role));
        }
        sleep(READY_POLL).await;
    }
}

/// SOCKS5 no-auth handshake, then `CONNECT target`. A refused CONNECT is
/// `PermissionDenied`.
pub async fn socks5_connect(socks: SocketAddr, target: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = socks5_handshake(socks).await?;
    socks5_command(&mut stream, Command::Connect, target).await?;
    Ok(stream)
}

/// CONNECT through `socks` to a fresh local echo server, send `payload`,
/// half-close, and read the echo back.
pub async fn socks5_echo_roundtrip(socks: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await?;
        let (mut reader, mut writer) = stream.split();
        tokio::io::copy(&mut reader, &mut writer).await
    });
    let echoed = async {
        let mut client = socks5_connect(socks, echo_addr).await?;
        client.write_all(payload).await?;
        client.shutdown().await?;
        let mut echoed = Vec::new();
        timeout(READY_TIMEOUT, client.read_to_end(&mut echoed))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "echo read timed out"))??;
        io::Result::Ok(echoed)
    }
    .await;
    if echoed.is_err() {
        server.abort();
        return echoed;
    }
    server.await.map_err(io::Error::other)??;
    echoed
}

/// SOCKS5 UDP ASSOCIATE. Returns the control stream, which must stay open
/// for the association's lifetime, the relay address, and a local socket.
pub async fn socks5_udp_associate(
    socks: SocketAddr,
) -> io::Result<(TcpStream, SocketAddr, UdpSocket)> {
    let mut control = socks5_handshake(socks).await?;
    let unspecified = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let relay = socks5_command(&mut control, Command::UdpAssociate, unspecified).await?;
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    Ok((control, relay, udp))
}

/// One SOCKS5 UDP datagram for `dest`.
pub fn socks5_udp_packet(dest: SocketAddr, frag: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 3 + MAX_UDP_PACKET_ADDR_LEN + payload.len()];
    let n = socks5::encode_udp_packet(&mut packet, frag, AddressRef::Ip(dest), payload)
        .expect("buffer sized for the header");
    packet.truncate(n);
    packet
}

/// A local UDP server that echoes every datagram to its sender.
pub async fn spawn_udp_echo() -> io::Result<SocketAddr> {
    let echo = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = echo.local_addr()?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });
    Ok(addr)
}

/// Echo `payload` through a fresh SOCKS5 UDP association to a local echo server.
pub async fn socks5_udp_echo_roundtrip(socks: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let echo = spawn_udp_echo().await?;
    let (_control, relay, udp) = socks5_udp_associate(socks).await?;
    udp.send_to(&socks5_udp_packet(echo, 0, payload), relay)
        .await?;
    let mut buf = vec![0u8; 65535];
    let (n, _) = timeout(READY_TIMEOUT, udp.recv_from(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "udp echo timed out"))??;
    let packet = socks5::parse_udp_packet(&buf[..n]).map_err(io::Error::other)?;
    if packet.frag != 0 {
        return Err(io::Error::other("fragmented udp reply"));
    }
    Ok(packet.payload.to_vec())
}

async fn socks5_handshake(socks: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream
        .write_all(&[socks5::VERSION, 1, socks5::METHOD_NO_AUTH])
        .await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [socks5::VERSION, socks5::METHOD_NO_AUTH] {
        return Err(io::Error::other("socks5 method negotiation failed"));
    }
    Ok(stream)
}

/// Send one request and return the bind address of a succeeded reply.
async fn socks5_command(
    stream: &mut TcpStream,
    command: Command,
    target: SocketAddr,
) -> io::Result<SocketAddr> {
    let mut buf = [0u8; socks5::MAX_REQUEST_LEN];
    let n = socks5::encode_request(&mut buf, command, AddressRef::Ip(target))
        .map_err(io::Error::other)?;
    stream.write_all(&buf[..n]).await?;
    let mut filled = 0;
    loop {
        match socks5::reply_need(&buf[..filled]).map_err(io::Error::other)? {
            ParseState::Need(total) => {
                stream.read_exact(&mut buf[filled..total]).await?;
                filled = total;
            }
            ParseState::Done(reply) => {
                return match (reply.reply, reply.bind) {
                    (Reply::Succeeded, AddressRef::Ip(bind)) => Ok(bind),
                    (Reply::Succeeded, bind) => {
                        Err(io::Error::other(format!("unexpected bind {bind}")))
                    }
                    (refused, _) => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("socks5 {command:?} refused: {refused:?}"),
                    )),
                };
            }
        }
    }
}

/// Minimal temp directory helper so the crate does not take `tempfile` as a
/// production-style extra framework. The directory is unique and removed on drop.
mod tempfile_dir {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new() -> std::io::Result<Self> {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("snell-oracle-{nanos}-{}", std::process::id()));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_not_found() {
        assert!(matches!(
            SnellBinary::from_path("/no/such/snell-rs"),
            Err(OracleError::BinaryNotFound(_))
        ));
    }
}

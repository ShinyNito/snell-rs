//! Spawn a Snell client/server pair as independent processes.
//!
//! The binary is located via `SNELL_RS_TEST_BIN`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
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
    Io(#[from] std::io::Error),
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

pub struct ProcessPair {
    _dir: tempfile_dir::TempDir,
    _server: Child,
    _client: Child,
    pub socks: SocketAddr,
    pub snell: SocketAddr,
}

impl ProcessPair {
    pub async fn spawn_v4(binary: &SnellBinary, psk: &str) -> Result<Self, OracleError> {
        Self::spawn(
            binary,
            psk,
            None,
            ClientOptions {
                version: "v4",
                reuse: false,
            },
        )
        .await
    }

    pub async fn spawn(
        binary: &SnellBinary,
        psk: &str,
        server_version: Option<&str>,
        client: ClientOptions,
    ) -> Result<Self, OracleError> {
        let mut last_error = None;
        for _ in 0..8 {
            match spawn_once(binary, psk, server_version, client).await {
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
    binary: &SnellBinary,
    psk: &str,
    server_version: Option<&str>,
    client: ClientOptions,
) -> Result<ProcessPair, OracleError> {
    let dir = tempfile_dir::TempDir::new()?;
    let snell = free_listen_addr().await?;
    let socks = free_listen_addr().await?;

    let server_conf = dir.path().join("snell-server.conf");
    let client_conf = dir.path().join("snell-client.conf");
    std::fs::write(&server_conf, server_ini(snell, psk, server_version))?;
    std::fs::write(&client_conf, client_ini(socks, snell, psk, client))?;

    let mut server = spawn_role(binary, "server", &server_conf)?;
    wait_listening(&mut server, snell, "server").await?;

    let mut client_proc = spawn_role(binary, "client", &client_conf)?;
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
    Ok(Command::new(binary.path())
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

fn server_ini(listen: SocketAddr, psk: &str, version: Option<&str>) -> String {
    match version {
        Some(version) => {
            format!("[snell-server]\nlisten = {listen}\npsk = {psk}\nversion = {version}\n")
        }
        None => format!("[snell-server]\nlisten = {listen}\npsk = {psk}\n"),
    }
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

/// SOCKS5 CONNECT through the client, then copy `payload` and read it back
/// from a local echo server reached via the server.
pub async fn socks5_echo_roundtrip(
    socks: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, OracleError> {
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await?;
        }
        std::io::Result::Ok(())
    });

    let mut client = TcpStream::connect(socks).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(std::io::Error::other("socks5 method negotiation failed").into());
    }

    let SocketAddr::V4(echo_v4) = echo_addr else {
        return Err(std::io::Error::other("echo server must be ipv4").into());
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&echo_v4.ip().octets());
    request.extend_from_slice(&echo_v4.port().to_be_bytes());
    client.write_all(&request).await?;

    let mut reply_head = [0u8; 4];
    client.read_exact(&mut reply_head).await?;
    if reply_head[0] != 0x05 || reply_head[1] != 0x00 {
        return Err(std::io::Error::other(format!("socks5 connect failed: {reply_head:?}")).into());
    }
    drain_socks5_bind(&mut client, reply_head[3]).await?;

    client.write_all(payload).await?;
    client.shutdown().await?;

    let mut echoed = Vec::new();
    timeout(READY_TIMEOUT, client.read_to_end(&mut echoed))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "echo read timed out"))??;
    server.await.map_err(std::io::Error::other)??;
    Ok(echoed)
}

async fn drain_socks5_bind(stream: &mut TcpStream, atyp: u8) -> Result<(), OracleError> {
    match atyp {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut rest).await?;
        }
        other => {
            return Err(std::io::Error::other(format!("unexpected socks5 atyp {other}")).into());
        }
    }
    Ok(())
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
    use snell_protocol::PSK_MIN_LEN;

    #[test]
    fn missing_file_is_not_found() {
        assert!(matches!(
            SnellBinary::from_path("/no/such/snell-rs"),
            Err(OracleError::BinaryNotFound(_))
        ));
    }

    #[test]
    fn psk_used_by_oracle_meets_minimum() {
        assert!(b"0123456789abcdef".len() >= PSK_MIN_LEN);
    }
}

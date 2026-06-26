use std::{
    collections::HashSet, future::Future, io, net::SocketAddr, path::PathBuf, process::ExitCode,
};
#[cfg(windows)]
use std::{num::NonZeroUsize, sync::Arc, thread};
#[cfg(all(
    unix,
    not(target_os = "solaris"),
    not(target_os = "illumos"),
    not(target_os = "cygwin"),
))]
use std::{
    sync::{Arc, mpsc},
    thread,
};

use clap::{ArgGroup, Args, Parser, Subcommand};
use snell_rs::client::ClientConfig as RuntimeClientConfig;
#[cfg(not(windows))]
use snell_rs::client::bind_tcp_listener as bind_client_tcp_listener;
#[cfg(windows)]
use snell_rs::client::bind_tcp_listener_with_dispatcher as bind_client_tcp_listener_with_dispatcher;
use snell_rs::config::{
    ClientConfig as FileClientConfig, ServerConfig as FileServerConfig, psk_from_str,
    server_protocol_from_cli,
};
use snell_rs::protocol::snell::version::ProtocolVersion;
#[cfg(not(windows))]
use snell_rs::server::bind_tcp_listener as bind_server_tcp_listener;
#[cfg(windows)]
use snell_rs::server::bind_tcp_listener_with_dispatcher as bind_server_tcp_listener_with_dispatcher;
use snell_rs::server::{Outbound, ServerConfig as RuntimeServerConfig};
use tracing_subscriber::EnvFilter;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(version, about = "Snell protocol SOCKS5 bridge")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a local SOCKS5 inbound that proxies through a Snell server.
    Client(ClientArgs),
    /// Run a Snell server.
    Server(ServerArgs),
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("client_src")
        .required(true)
        .args(["config", "socks_listen"]),
))]
struct ClientArgs {
    /// Path to an INI config file.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["socks_listen", "snell_server", "psk", "version"])]
    config: Option<PathBuf>,
    /// SOCKS5 listen address, for example 127.0.0.1:1080.
    #[arg(requires_all = ["snell_server", "psk", "version"])]
    socks_listen: Option<SocketAddr>,
    /// Snell server address, for example 127.0.0.1:8388.
    snell_server: Option<SocketAddr>,
    /// Pre-shared key, taken as raw UTF-8 bytes.
    psk: Option<String>,
    /// Protocol version: v4, v5, v6-default, v6-unshaped, or v6-unsafe-raw.
    #[arg(value_parser = ProtocolVersion::parse)]
    version: Option<ProtocolVersion>,
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("server_src")
        .required(true)
        .args(["config", "snell_listen"]),
))]
struct ServerArgs {
    /// Path to an INI config file.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["snell_listen", "psk", "version", "mode", "socks5_outbound"])]
    config: Option<PathBuf>,
    /// Snell listen address, for example 0.0.0.0:8388.
    #[arg(requires = "psk")]
    snell_listen: Option<SocketAddr>,
    /// Pre-shared key, taken as raw UTF-8 bytes.
    psk: Option<String>,
    /// Optional server protocol version: 4, 5, or 6. Omit for auto-probe.
    version: Option<String>,
    /// Optional v6 mode. Only valid when version is 6.
    mode: Option<String>,
    /// Optional upstream SOCKS5 proxy for outbound connections.
    #[arg(long = "socks5-outbound", value_name = "ADDR")]
    socks5_outbound: Option<SocketAddr>,
}

fn main() -> ExitCode {
    init_tracing();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    match Cli::parse().cmd {
        Cmd::Client(args) => {
            let config = client_config(args)?;
            tracing::info!(
                listen = %config.listen,
                server = %config.server,
                resume = config.resume,
                version = ?config.version,
                "snell-rs client listening",
            );
            run_client(config)
        }
        Cmd::Server(args) => {
            let (config, protocol) = server_config(args)?;
            tracing::info!(
                listen = %config.listen,
                outbound = ?config.outbound,
                tcp_brutal = config.tcp_brutal.is_some(),
                tcp_brutal_rate = config.tcp_brutal.map(|config| config.rate_bytes_per_sec),
                tcp_brutal_cwnd_gain = config.tcp_brutal.map(|config| config.cwnd_gain),
                parsed_protocol = ?protocol,
                "snell-rs server listening",
            );
            run_server(config)
        }
    }
}

#[cfg(not(windows))]
fn run_client(config: RuntimeClientConfig) -> io::Result<()> {
    run_per_core(move |worker| block_on_worker(worker, bind_client_tcp_listener(config.clone())))
}

#[cfg(windows)]
fn run_client(config: RuntimeClientConfig) -> io::Result<()> {
    run_with_dispatcher(move |dispatcher| {
        bind_client_tcp_listener_with_dispatcher(config, dispatcher)
    })
}

#[cfg(not(windows))]
fn run_server(config: RuntimeServerConfig) -> io::Result<()> {
    run_per_core(move |worker| block_on_worker(worker, bind_server_tcp_listener(config.clone())))
}

#[cfg(windows)]
fn run_server(config: RuntimeServerConfig) -> io::Result<()> {
    run_with_dispatcher(move |dispatcher| {
        bind_server_tcp_listener_with_dispatcher(config, dispatcher)
    })
}

#[cfg(windows)]
fn run_with_dispatcher<F, Fut>(run_acceptor: F) -> io::Result<()>
where
    F: FnOnce(Arc<compio::dispatcher::Dispatcher>) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    block_on_worker(0, async move {
        let workers =
            thread::available_parallelism().unwrap_or_else(|_| NonZeroUsize::new(1).unwrap());
        let dispatcher = Arc::new(
            compio::dispatcher::Dispatcher::builder()
                .worker_threads(workers)
                .thread_affinity(|worker| {
                    let mut cpus = HashSet::new();
                    cpus.insert(worker);
                    cpus
                })
                .thread_names(|worker| format!("snell-rs-worker-{worker}"))
                .build()?,
        );
        run_acceptor(dispatcher).await
    })
}

#[cfg(not(windows))]
fn run_per_core<F>(run_worker: F) -> io::Result<()>
where
    F: Fn(usize) -> io::Result<()> + Send + Sync + 'static,
{
    #[cfg(not(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin"),
    )))]
    {
        run_worker(0)
    }

    #[cfg(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin"),
    ))]
    {
        let workers = thread::available_parallelism().map_or(1, usize::from);
        let run_worker = Arc::new(run_worker);
        let (tx, rx) = mpsc::channel();

        for worker in 0..workers {
            let tx = tx.clone();
            let run_worker = run_worker.clone();
            thread::Builder::new()
                .name(format!("snell-rs-worker-{worker}"))
                .spawn(move || {
                    let result = run_worker(worker);
                    let _ = tx.send(result);
                })?;
        }
        drop(tx);

        rx.recv()
            .unwrap_or_else(|_| Err(io::Error::other("all runtime workers exited")))
    }
}

fn block_on_worker<F>(worker: usize, future: F) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
{
    let mut cpus = HashSet::new();
    cpus.insert(worker);
    compio::runtime::Runtime::builder()
        .thread_affinity(cpus)
        .build()?
        .block_on(future)
}

fn client_config(args: ClientArgs) -> io::Result<RuntimeClientConfig> {
    let config = if let Some(path) = args.config {
        let cfg = FileClientConfig::load(path)?;
        RuntimeClientConfig {
            listen: cfg.listen,
            server: cfg.server,
            psk: cfg.psk,
            resume: cfg.reuse,
            version: cfg.version,
        }
    } else {
        RuntimeClientConfig {
            listen: args.socks_listen.expect("required by clap arg group"),
            server: args.snell_server.expect("required by clap arg group"),
            psk: psk_from_str(&args.psk.expect("required by clap arg group"))?,
            resume: false,
            version: args.version.expect("required by clap arg group"),
        }
    };
    Ok(config)
}

fn server_config(args: ServerArgs) -> io::Result<(RuntimeServerConfig, Option<ProtocolVersion>)> {
    if let Some(path) = args.config {
        let cfg = FileServerConfig::load(path)?;
        let outbound = cfg
            .upstream_socks5
            .map_or(Outbound::Direct, |server| Outbound::Socks5 { server });
        return Ok((
            RuntimeServerConfig {
                listen: cfg.listen,
                psk: cfg.psk,
                outbound,
                tcp_brutal: cfg.tcp_brutal,
            },
            cfg.protocol,
        ));
    }

    let protocol = server_protocol_from_cli(args.version.as_deref(), args.mode.as_deref())?;
    Ok((
        RuntimeServerConfig {
            listen: args.snell_listen.expect("required by clap arg group"),
            psk: psk_from_str(&args.psk.expect("required by clap arg group"))?,
            outbound: args
                .socks5_outbound
                .map_or(Outbound::Direct, |server| Outbound::Socks5 { server }),
            tcp_brutal: None,
        },
        protocol,
    ))
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

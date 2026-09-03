use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand};
use snell_config::{ClientConfig as FileClientConfig, ServerConfig as FileServerConfig};
use snell_runtime::{
    ClientConfig, Outbound, ProtocolSelection, ServerConfig, TcpBrutal, UdpOptions, run_client,
    run_server,
};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "snell-rs", version, about = "Snell client/server")]
struct Cli {
    /// Log filter (`info`, `debug`, `snell_runtime=debug`). `RUST_LOG` wins if set.
    #[arg(long = "log-level", global = true, value_name = "FILTER")]
    log_level: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the snell-rs version.
    Version,
    /// SOCKS5 inbound that proxies through a Snell server.
    Client(ClientArgs),
    /// Snell server.
    Server(ServerArgs),
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("client_src")
        .required(true)
        .args(["config", "listen"]),
))]
struct ClientArgs {
    /// Path to an INI config file.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["listen", "server", "psk", "version", "reuse"])]
    config: Option<PathBuf>,
    /// SOCKS5 listen address.
    #[arg(requires_all = ["server", "psk", "version"])]
    listen: Option<SocketAddr>,
    server: Option<SocketAddr>,
    psk: Option<String>,
    version: Option<String>,
    /// Enable CONNECT_V2 client reuse.
    #[arg(long)]
    reuse: bool,
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("server_src")
        .required(true)
        .args(["config", "listen"]),
))]
struct ServerArgs {
    /// Path to an INI config file.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["listen", "psk", "version", "mode", "socks5_outbound"])]
    config: Option<PathBuf>,
    /// Snell listen address.
    #[arg(requires = "psk")]
    listen: Option<SocketAddr>,
    psk: Option<String>,
    version: Option<String>,
    mode: Option<String>,
    #[arg(long = "socks5-outbound", value_name = "ADDR")]
    socks5_outbound: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("snell-rs {}", env!("CARGO_PKG_VERSION"));
        }
        Command::Client(args) => {
            init_logging(cli.log_level.as_deref());
            run_client(client_config(args)?).await?;
        }
        Command::Server(args) => {
            init_logging(cli.log_level.as_deref());
            run_server(server_config(args)?).await?;
        }
    }
    Ok(())
}

fn init_logging(log_level: Option<&str>) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level.unwrap_or("info")));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
                .with_target(false)
                .compact(),
        )
        .init();
}

fn client_config(args: ClientArgs) -> anyhow::Result<ClientConfig> {
    if let Some(path) = args.config {
        let cfg = FileClientConfig::load(path)?;
        return Ok(ClientConfig {
            listen: cfg.listen,
            server: cfg.server,
            psk: cfg.psk,
            version: cfg.version,
            reuse: cfg.reuse,
            pool: None,
            udp: UdpOptions::new()?,
        });
    }
    Ok(ClientConfig {
        listen: args.listen.expect("required by clap"),
        server: args.server.expect("required by clap"),
        psk: snell_config::parse_psk_str(&args.psk.expect("required by clap"))?,
        version: snell_config::parse_client_version(&args.version.expect("required by clap"))?,
        reuse: args.reuse,
        pool: None,
        udp: UdpOptions::new()?,
    })
}

fn server_config(args: ServerArgs) -> anyhow::Result<ServerConfig> {
    if let Some(path) = args.config {
        let cfg = FileServerConfig::load(path)?;
        return Ok(ServerConfig {
            listen: cfg.listen,
            psk: cfg.psk,
            selection: cfg.selection,
            outbound: map_outbound(cfg.outbound),
            udp: UdpOptions::new()?,
            tcp_brutal: cfg.tcp_brutal.map(|brutal| TcpBrutal {
                send_mbps: brutal.send_mbps,
                cwnd_gain: brutal.cwnd_gain,
            }),
        });
    }
    if args.version.is_none() && args.mode.is_some() {
        anyhow::bail!("mode is only valid when version = 6");
    }
    let selection = match args.version.as_deref() {
        None => ProtocolSelection::Auto,
        Some(version) => ProtocolSelection::Exact(snell_config::parse_server_version(
            version,
            args.mode.as_deref(),
        )?),
    };
    Ok(ServerConfig {
        listen: args.listen.expect("required by clap"),
        psk: snell_config::parse_psk_str(&args.psk.expect("required by clap"))?,
        selection,
        outbound: match args.socks5_outbound {
            Some(server) => Outbound::Socks5 { server },
            None => Outbound::Direct,
        },
        udp: UdpOptions::new()?,
        tcp_brutal: None,
    })
}

fn map_outbound(outbound: snell_config::Outbound) -> Outbound {
    match outbound {
        snell_config::Outbound::Direct => Outbound::Direct,
        snell_config::Outbound::Socks5 { server } => Outbound::Socks5 { server },
    }
}

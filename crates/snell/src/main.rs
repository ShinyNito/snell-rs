use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand};
use snell_config::{ClientConfig as FileClientConfig, ServerConfig as FileServerConfig};
use snell_runtime::{ClientConfig, Outbound, ServerConfig, run_client, run_server};

#[derive(Parser)]
#[command(name = "snell-rs", version, about = "Snell client/server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print toolchain and phase status.
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
    #[arg(long, value_name = "FILE", conflicts_with_all = ["listen", "server", "psk", "version"])]
    config: Option<PathBuf>,
    /// SOCKS5 listen address.
    #[arg(requires_all = ["server", "psk", "version"])]
    listen: Option<SocketAddr>,
    server: Option<SocketAddr>,
    psk: Option<String>,
    version: Option<String>,
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
    match Cli::parse().command {
        Command::Version => {
            println!(
                "snell-rs {} (current phase stops after Phase 5)",
                env!("CARGO_PKG_VERSION")
            );
        }
        Command::Client(args) => {
            run_client(client_config(args)?).await?;
        }
        Command::Server(args) => {
            run_server(server_config(args)?).await?;
        }
    }
    Ok(())
}

fn client_config(args: ClientArgs) -> anyhow::Result<ClientConfig> {
    if let Some(path) = args.config {
        let cfg = FileClientConfig::load(path)?;
        return Ok(ClientConfig {
            listen: cfg.listen,
            server: cfg.server,
            psk: cfg.psk,
            version: cfg.version,
        });
    }
    Ok(ClientConfig {
        listen: args.listen.expect("required by clap"),
        server: args.server.expect("required by clap"),
        psk: snell_config::parse_psk_str(&args.psk.expect("required by clap"))?,
        version: snell_config::parse_client_version(&args.version.expect("required by clap"))?,
    })
}

fn server_config(args: ServerArgs) -> anyhow::Result<ServerConfig> {
    if let Some(path) = args.config {
        let cfg = FileServerConfig::load(path)?;
        return Ok(ServerConfig {
            listen: cfg.listen,
            psk: cfg.psk,
            version: cfg.version,
            outbound: map_outbound(cfg.outbound),
        });
    }
    let version = args
        .version
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("server auto-detect is not implemented in this phase"))?;
    Ok(ServerConfig {
        listen: args.listen.expect("required by clap"),
        psk: snell_config::parse_psk_str(&args.psk.expect("required by clap"))?,
        version: snell_config::parse_server_version(version, args.mode.as_deref())?,
        outbound: match args.socks5_outbound {
            Some(server) => Outbound::Socks5 { server },
            None => Outbound::Direct,
        },
    })
}

fn map_outbound(outbound: snell_config::Outbound) -> Outbound {
    match outbound {
        snell_config::Outbound::Direct => Outbound::Direct,
        snell_config::Outbound::Socks5 { server } => Outbound::Socks5 { server },
    }
}

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use snell_rs::service::runtime::client::bind_configured_socks5_client_with_shutdown;
use snell_rs::service::runtime::config::{ClientConfig, ServerConfig};
use snell_rs::service::runtime::server::bind_configured_tcp_server_with_shutdown;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "snell-rs", version, about = "Snell proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server {
        #[arg(long, value_name = "snell-server.conf")]
        config: PathBuf,
    },
    Client {
        #[arg(long, value_name = "snell-client.conf")]
        config: PathBuf,
    },
    Version,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    init_tracing()?;

    match cli.command {
        Command::Server { config } => {
            let config = ServerConfig::load_from_file(config)?;
            tracing::info!(
                listen = ?config.listen,
                version = config.version,
                quic_proxy = config.quic_proxy,
                ipv6 = config.ipv6,
                tcp_fast_open = config.tcp_fast_open,
                tcp_brutal = config.tcp_brutal.is_some(),
                tcp_brutal_rate = config.tcp_brutal.map(|config| config.rate_bytes_per_sec),
                upstream_socks5 = ?config.upstream_socks5.map(|upstream| upstream.addr),
                "starting snell server"
            );
            let shutdown = tokio_util::sync::CancellationToken::new();
            let service = bind_configured_tcp_server_with_shutdown(config, shutdown.clone());
            tokio::pin!(service);
            tokio::select! {
                result = &mut service => result?,
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    tracing::info!("received shutdown signal");
                    shutdown.cancel();
                    service.await?;
                }
            }
        }
        Command::Client { config } => {
            let config = ClientConfig::load_from_file(config)?;
            tracing::info!(
                listen = %config.listen,
                server = %config.server,
                version = config.version,
                reuse = config.reuse,
                quic_proxy = config.quic_proxy,
                "starting snell client"
            );
            let shutdown = tokio_util::sync::CancellationToken::new();
            let service = bind_configured_socks5_client_with_shutdown(config, shutdown.clone());
            tokio::pin!(service);
            tokio::select! {
                result = &mut service => result?,
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    tracing::info!("received shutdown signal");
                    shutdown.cancel();
                    service.await?;
                }
            }
        }
        Command::Version => {
            println!("{}", version_text());
        }
    }

    Ok(())
}

fn version_text() -> String {
    format!(
        "snell-rs {} (commit {})",
        env!("CARGO_PKG_VERSION"),
        env!("SNELL_RS_GIT_COMMIT")
    )
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_env("SNELL_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("warn,snell_rs=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .try_init()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::{CommandFactory, Parser};

    use super::{Cli, Command, version_text};

    #[test]
    fn parses_server_config_path() {
        let cli =
            Cli::try_parse_from(["snell-rs", "server", "--config", "snell-server.conf"]).unwrap();

        match cli.command {
            Command::Server { config } => {
                assert_eq!(config, PathBuf::from("snell-server.conf"));
            }
            Command::Client { .. } | Command::Version => panic!("expected server command"),
        }
    }

    #[test]
    fn parses_client_config_option() {
        let cli =
            Cli::try_parse_from(["snell-rs", "client", "--config", "snell-client.conf"]).unwrap();

        match cli.command {
            Command::Client { config } => {
                assert_eq!(config, PathBuf::from("snell-client.conf"));
            }
            Command::Server { .. } | Command::Version => panic!("expected client command"),
        }
    }

    #[test]
    fn help_mentions_config_shapes() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();

        assert!(help.contains("server"));
        assert!(help.contains("client"));
        assert!(help.contains("version"));

        let mut command = Cli::command();
        let server_help = command
            .find_subcommand_mut("server")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(server_help.contains("--config <snell-server.conf>"));

        let mut command = Cli::command();
        let client_help = command
            .find_subcommand_mut("client")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(client_help.contains("--config <snell-client.conf>"));
    }

    #[test]
    fn parses_version_command() {
        let cli = Cli::try_parse_from(["snell-rs", "version"]).unwrap();

        match cli.command {
            Command::Version => {}
            Command::Server { .. } | Command::Client { .. } => panic!("expected version command"),
        }
    }

    #[test]
    fn version_text_contains_package_version_and_commit() {
        let text = version_text();

        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(text.contains(env!("SNELL_RS_GIT_COMMIT")));
    }
}

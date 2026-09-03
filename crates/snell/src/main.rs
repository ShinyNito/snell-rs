use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "snell-rs", version, about = "Snell client/server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print toolchain and phase status. Protocol runtime is not implemented yet.
    Version,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Version => {
            let _ = snell_config::protocol::PROTOCOL_VERSION;
            let _ = snell_runtime::protocol::PROTOCOL_VERSION;
            println!(
                "snell-rs {} (current phase stops after Phase 1)",
                env!("CARGO_PKG_VERSION")
            );
        }
    }
    Ok(())
}

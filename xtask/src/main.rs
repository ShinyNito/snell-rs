use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Development tasks for snell-rs")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Run the Phase 0/1 workspace gates.
    Check,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Task::Check => {
            if let Err(error) = check() {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

fn check() -> anyhow::Result<()> {
    run(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))?;
    run(Command::new("cargo").args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ]))?;
    run(Command::new("cargo").args(["nextest", "run", "--workspace", "--all-features"]))?;
    run(Command::new("cargo").args(["deny", "check"]))?;
    Ok(())
}

fn run(command: &mut Command) -> anyhow::Result<()> {
    let status = command.status()?;
    anyhow::ensure!(status.success(), "command failed: {command:?}");
    Ok(())
}

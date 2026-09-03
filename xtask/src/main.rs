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
    /// Run fmt, clippy, nextest, and cargo deny.
    Check,
    /// Process-level TCP echo soak (`SNELL_SOAK_SECS`, default 15).
    Soak,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Task::Check => finish(check()),
        Task::Soak => finish(soak()),
    }
}

fn finish(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
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

fn soak() -> anyhow::Result<()> {
    run(Command::new("cargo").args([
        "test",
        "-p",
        "snell",
        "--test",
        "soak",
        "--",
        "--ignored",
        "--nocapture",
    ]))
}

fn run(command: &mut Command) -> anyhow::Result<()> {
    let status = command.status()?;
    anyhow::ensure!(status.success(), "command failed: {command:?}");
    Ok(())
}

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
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Task::Check => finish(check()),
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
        "--locked",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ]))?;
    let has_nextest = Command::new("cargo")
        .args(["nextest", "--version"])
        .output()
        .is_ok_and(|output| output.status.success());
    let test = if has_nextest {
        vec![
            "nextest",
            "run",
            "--workspace",
            "--locked",
            "--all-features",
        ]
    } else {
        vec!["test", "--workspace", "--locked", "--all-features"]
    };
    run(Command::new("cargo").args(test))?;
    run(Command::new("cargo").args(["deny", "check"]))?;
    Ok(())
}

fn run(command: &mut Command) -> anyhow::Result<()> {
    let status = command.status()?;
    anyhow::ensure!(status.success(), "command failed: {command:?}");
    Ok(())
}

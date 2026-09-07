use std::path::PathBuf;
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
    /// Run fmt, clippy, real process tests, doctests, and cargo deny.
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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    std::env::set_current_dir(&root)?;
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
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let target = if target.is_absolute() {
        target
    } else {
        root.join(target)
    };
    run(Command::new("cargo")
        .args(["build", "-p", "snell", "--all-features", "--target-dir"])
        .arg(&target))?;
    let target = match std::env::var_os("CARGO_BUILD_TARGET") {
        Some(triple) => target.join(triple),
        None => target,
    };
    let binary = target
        .join("debug")
        .join(format!("snell-rs{}", std::env::consts::EXE_SUFFIX));
    anyhow::ensure!(
        binary.is_file(),
        "process-test binary missing: {}",
        binary.display()
    );
    let nextest = Command::new("cargo")
        .args(["nextest", "--version"])
        .output()?
        .status
        .success();
    if nextest {
        run(Command::new("cargo")
            .args([
                "nextest",
                "run",
                "--workspace",
                "--all-features",
                "--run-ignored",
                "all",
            ])
            .env("SNELL_RS_TEST_BIN", &binary))?;
        run(Command::new("cargo").args(["test", "--doc", "--workspace", "--all-features"]))?;
    } else {
        run(Command::new("cargo")
            .args([
                "test",
                "--workspace",
                "--all-features",
                "--",
                "--include-ignored",
            ])
            .env("SNELL_RS_TEST_BIN", &binary))?;
    }
    run(Command::new("cargo").args(["deny", "check"]))?;
    Ok(())
}

fn run(command: &mut Command) -> anyhow::Result<()> {
    let status = command.status()?;
    anyhow::ensure!(status.success(), "command failed: {command:?}");
    Ok(())
}

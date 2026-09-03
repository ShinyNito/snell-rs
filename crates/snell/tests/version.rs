use std::process::Command;

#[test]
fn version_subcommand_matches_package() {
    let output = Command::new(env!("CARGO_BIN_EXE_snell-rs"))
        .arg("version")
        .output()
        .expect("spawn snell-rs version");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert_eq!(
        stdout.trim(),
        format!("snell-rs {}", env!("CARGO_PKG_VERSION"))
    );
}

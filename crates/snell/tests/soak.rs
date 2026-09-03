//! Process-level soak. Ignored in the default suite.
//!
//! ```bash
//! SNELL_SOAK_SECS=30 cargo test -p snell --test soak -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use snell_testkit::oracle::{ClientOptions, ProcessPair, SnellBinary, socks5_echo_roundtrip};

const PSK: &str = "0123456789abcdef";
const DEFAULT_SECS: u64 = 15;

fn workspace_bin() -> SnellBinary {
    match SnellBinary::from_env() {
        Ok(binary) => binary,
        Err(_) => SnellBinary::from_path(env!("CARGO_BIN_EXE_snell-rs"))
            .expect("workspace snell-rs binary"),
    }
}

fn soak_secs() -> u64 {
    std::env::var("SNELL_SOAK_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_SECS)
}

#[tokio::test]
#[ignore]
async fn soak_v4_tcp_echo() {
    let secs = soak_secs();
    let pair = ProcessPair::spawn(
        &workspace_bin(),
        PSK,
        Some("4"),
        ClientOptions {
            version: "v4",
            reuse: false,
        },
    )
    .await
    .expect("pair");

    let payload = b"soak-v4";
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut rounds = 0u64;
    while Instant::now() < deadline {
        let echoed = socks5_echo_roundtrip(pair.socks, payload)
            .await
            .unwrap_or_else(|error| panic!("soak round {rounds}: {error}"));
        assert_eq!(echoed, payload);
        rounds += 1;
    }
    assert!(rounds > 0, "soak produced no successful rounds");
    eprintln!("soak_v4_tcp_echo rounds={rounds} secs={secs}");
}

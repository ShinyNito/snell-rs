use snell_testkit::oracle::{ClientOptions, ProcessPair, SnellBinary, socks5_echo_roundtrip};

const PSK: &str = "0123456789abcdef";

fn workspace_bin() -> SnellBinary {
    SnellBinary::from_path(env!("CARGO_BIN_EXE_snell-rs")).expect("workspace snell-rs binary")
}

#[tokio::test]
async fn new_v4_process_echo() {
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
    let payload = b"new-new-v4";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn new_v5_process_echo() {
    let pair = ProcessPair::spawn(
        &workspace_bin(),
        PSK,
        Some("5"),
        ClientOptions {
            version: "v5",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"new-new-v5";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn new_v6_shaped_process_echo() {
    let pair = ProcessPair::spawn(
        &workspace_bin(),
        PSK,
        Some("6"),
        ClientOptions {
            version: "v6-default",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"new-new-v6-shaped";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn new_v6_unshaped_process_echo() {
    let pair = ProcessPair::spawn_with_mode(
        &workspace_bin(),
        PSK,
        Some("6"),
        Some("unshaped"),
        ClientOptions {
            version: "v6-unshaped",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"new-new-v6-unshaped";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

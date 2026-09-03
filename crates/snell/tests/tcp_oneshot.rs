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

#[tokio::test]
async fn new_v4_reuse_two_echoes() {
    let pair = ProcessPair::spawn(
        &workspace_bin(),
        PSK,
        Some("4"),
        ClientOptions {
            version: "v4",
            reuse: true,
        },
    )
    .await
    .expect("pair");
    for i in 0..2 {
        let payload = format!("new-reuse-v4-{i}").into_bytes();
        let echoed = socks5_echo_roundtrip(pair.socks, &payload)
            .await
            .unwrap_or_else(|error| panic!("reuse echo {i}: {error}"));
        assert_eq!(echoed, payload);
    }
}

#[tokio::test]
async fn new_v6_shaped_reuse_two_echoes() {
    let pair = ProcessPair::spawn(
        &workspace_bin(),
        PSK,
        Some("6"),
        ClientOptions {
            version: "v6-default",
            reuse: true,
        },
    )
    .await
    .expect("pair");
    for i in 0..2 {
        let payload = format!("new-reuse-v6-{i}").into_bytes();
        let echoed = socks5_echo_roundtrip(pair.socks, &payload)
            .await
            .unwrap_or_else(|error| panic!("reuse echo {i}: {error}"));
        assert_eq!(echoed, payload);
    }
}

#[tokio::test]
async fn new_auto_server_v4_client() {
    let pair = ProcessPair::spawn(
        &workspace_bin(),
        PSK,
        None,
        ClientOptions {
            version: "v4",
            reuse: false,
        },
    )
    .await
    .expect("auto pair");
    let payload = b"new-auto-v4";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

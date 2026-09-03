use snell_testkit::oracle::{ClientOptions, ProcessPair, SnellBinary, socks5_echo_roundtrip};

const PSK: &str = "0123456789abcdef";

fn workspace_bin() -> SnellBinary {
    SnellBinary::from_path(env!("CARGO_BIN_EXE_snell-rs")).expect("workspace snell-rs binary")
}

fn legacy_bin() -> Option<SnellBinary> {
    match SnellBinary::from_env() {
        Ok(binary) => Some(binary),
        Err(_) => {
            eprintln!("skipping interop: set SNELL_RS_TEST_BIN to a legacy Snell binary");
            None
        }
    }
}

#[tokio::test]
async fn new_client_legacy_server_v4() {
    let Some(legacy) = legacy_bin() else {
        return;
    };
    let pair = ProcessPair::spawn_binaries(
        &legacy,
        &workspace_bin(),
        PSK,
        Some("4"),
        None,
        ClientOptions {
            version: "v4",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"new-client-legacy-server-v4";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn legacy_client_new_server_v4() {
    let Some(legacy) = legacy_bin() else {
        return;
    };
    let pair = ProcessPair::spawn_binaries(
        &workspace_bin(),
        &legacy,
        PSK,
        Some("4"),
        None,
        ClientOptions {
            version: "v4",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"legacy-client-new-server-v4";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn new_client_legacy_server_v5() {
    let Some(legacy) = legacy_bin() else {
        return;
    };
    let pair = ProcessPair::spawn_binaries(
        &legacy,
        &workspace_bin(),
        PSK,
        Some("5"),
        None,
        ClientOptions {
            version: "v5",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"new-client-legacy-server-v5";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn new_client_legacy_server_v6_shaped() {
    let Some(legacy) = legacy_bin() else {
        return;
    };
    let pair = ProcessPair::spawn_binaries(
        &legacy,
        &workspace_bin(),
        PSK,
        Some("6"),
        None,
        ClientOptions {
            version: "v6-default",
            reuse: false,
        },
    )
    .await
    .expect("pair");
    let payload = b"new-client-legacy-server-v6";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn legacy_client_new_server_v6_unshaped() {
    let Some(legacy) = legacy_bin() else {
        return;
    };
    let pair = ProcessPair::spawn_binaries(
        &workspace_bin(),
        &legacy,
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
    let payload = b"legacy-client-new-server-unshaped";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

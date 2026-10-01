use snell_testkit::oracle::{
    ClientOptions, ProcessPair, ServerOptions, SnellBinary, socks5_echo_roundtrip,
};

const PSK: &str = "0123456789abcdef";

/// Echo `rounds` payloads through a fresh process pair. With `reuse`, every
/// round after the first rides the pooled Snell connection.
async fn process_echo(server: ServerOptions, client: ClientOptions, rounds: usize) {
    let binary =
        SnellBinary::from_path(env!("CARGO_BIN_EXE_snell-rs")).expect("workspace snell-rs binary");
    let pair = ProcessPair::spawn(&binary, PSK, server, client)
        .await
        .expect("pair");
    for round in 0..rounds {
        let payload = format!("{server:?} {client:?} round {round}").into_bytes();
        let echoed = socks5_echo_roundtrip(pair.socks, &payload)
            .await
            .unwrap_or_else(|error| panic!("echo {round}: {error}"));
        assert_eq!(echoed, payload);
    }
}

fn server(version: &'static str) -> ServerOptions {
    ServerOptions {
        version: Some(version),
        mode: None,
    }
}

fn client(version: &'static str, reuse: bool) -> ClientOptions {
    ClientOptions { version, reuse }
}

#[tokio::test]
async fn v4_process_echo() {
    process_echo(server("4"), client("v4", false), 1).await;
}

#[tokio::test]
async fn v5_process_echo() {
    process_echo(server("5"), client("v5", false), 1).await;
}

#[tokio::test]
async fn v6_shaped_process_echo() {
    process_echo(server("6"), client("v6-default", false), 1).await;
}

#[tokio::test]
async fn v6_unshaped_process_echo() {
    let server = ServerOptions {
        version: Some("6"),
        mode: Some("unshaped"),
    };
    process_echo(server, client("v6-unshaped", false), 1).await;
}

#[tokio::test]
async fn v4_reuse_process_echoes() {
    process_echo(server("4"), client("v4", true), 2).await;
}

#[tokio::test]
async fn v6_shaped_reuse_process_echoes() {
    process_echo(server("6"), client("v6-default", true), 2).await;
}

#[tokio::test]
async fn auto_server_v4_client_process_echo() {
    process_echo(ServerOptions::default(), client("v4", false), 1).await;
}

use snell_testkit::oracle::{
    ClientOptions, ProcessPair, ServerOptions, SnellBinary, socks5_udp_echo_roundtrip,
};

const PSK: &str = "0123456789abcdef";

#[tokio::test]
async fn v4_process_udp_echo() {
    let binary =
        SnellBinary::from_path(env!("CARGO_BIN_EXE_snell-rs")).expect("workspace snell-rs binary");
    let server = ServerOptions {
        version: Some("4"),
        mode: None,
    };
    let pair = ProcessPair::spawn(&binary, PSK, server, ClientOptions::default())
        .await
        .expect("pair");
    let payload = b"process-v4-udp";
    let echoed = socks5_udp_echo_roundtrip(pair.socks, payload)
        .await
        .expect("echo");
    assert_eq!(echoed, payload);
}

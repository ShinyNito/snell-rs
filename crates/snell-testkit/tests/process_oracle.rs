use snell_testkit::load;
use snell_testkit::oracle::{ClientOptions, ProcessPair, SnellBinary, socks5_echo_roundtrip};
use tokio::sync::Mutex;

const PSK: &str = "0123456789abcdef";
static ORACLE_LOCK: Mutex<()> = Mutex::const_new(());

#[tokio::test]
#[ignore = "requires SNELL_RS_TEST_BIN; cargo xtask check builds and runs this"]
async fn v4_socks5_echo_roundtrip() {
    let binary = process_bin();
    let _lock = ORACLE_LOCK.lock().await;

    let pair = ProcessPair::spawn_v4(&binary, PSK)
        .await
        .expect("client/server must start");
    let payload = b"phase-1-oracle-ping";
    let echoed = socks5_echo_roundtrip(pair.socks, payload)
        .await
        .expect("SOCKS5 echo");
    assert_eq!(echoed, payload);
}

#[tokio::test]
#[ignore = "requires SNELL_RS_TEST_BIN; cargo xtask check builds and runs this"]
async fn v4_reuse_two_echoes() {
    let binary = process_bin();
    let _lock = ORACLE_LOCK.lock().await;

    let pair = ProcessPair::spawn(
        &binary,
        PSK,
        None,
        ClientOptions {
            version: "v4",
            reuse: true,
        },
    )
    .await
    .expect("reuse pair must start");
    for i in 0..2 {
        let payload = format!("reuse-echo-{i}").into_bytes();
        let echoed = socks5_echo_roundtrip(pair.socks, &payload)
            .await
            .unwrap_or_else(|error| panic!("reuse echo {i}: {error}"));
        assert_eq!(echoed, payload);
    }
}

#[tokio::test]
#[ignore = "requires SNELL_RS_TEST_BIN; cargo xtask check builds and runs this"]
async fn v4_throughput_64kib_x16() {
    let binary = process_bin();
    let _lock = ORACLE_LOCK.lock().await;

    let pair = ProcessPair::spawn_v4(&binary, PSK)
        .await
        .expect("pair must start");
    let payload = vec![0xA5; 64 * 1024];
    let report = load::tcp_echo_throughput(&pair, &payload, 16)
        .await
        .expect("throughput");
    println!(
        "v4 loopback: bytes={} elapsed={:?} mbps={:.3}",
        report.bytes,
        report.elapsed,
        report.bits_per_second() / 1_000_000.0
    );
    assert_eq!(report.bytes, 64 * 1024 * 16);
}

fn process_bin() -> SnellBinary {
    SnellBinary::from_env().expect("set SNELL_RS_TEST_BIN to the built binary")
}

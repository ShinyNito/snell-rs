//! Load through the binary named by `SNELL_RS_TEST_BIN`, such as a release
//! build. Echo and reuse scenarios run against the workspace binary in
//! `snell`'s process tests.

use snell_testkit::load;
use snell_testkit::oracle::{ClientOptions, ProcessPair, ServerOptions, SnellBinary};

const PSK: &str = "0123456789abcdef";

#[tokio::test]
#[ignore = "requires SNELL_RS_TEST_BIN; cargo xtask check builds and runs this"]
async fn v4_throughput_64kib_x16() {
    let binary = SnellBinary::from_env().expect("set SNELL_RS_TEST_BIN to the built binary");
    let pair = ProcessPair::spawn(
        &binary,
        PSK,
        ServerOptions::default(),
        ClientOptions::default(),
    )
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

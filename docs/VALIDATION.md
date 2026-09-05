# Validation results

## Revisions and environment

Production source under final local validation: `ec020bc3edc05f7c53d31be6b286915ec795b0b5`. The local build used Rust 1.98.0 (LLVM 22.1.8), `x86_64-unknown-linux-gnu`, glibc 2.41, Linux 6.18.35 and an AMD EPYC 9V74 host with a four-CPU cgroup quota. Release builds used the repository profile without PGO or additional target-cpu flags. Measurements used two Tokio workers per proxy process and separate client, server and load processes.

The first local comparison used `5c3c4312189c4b10fd462df47fe67babaa1f8981` as baseline, not main. This baseline already includes the initial KDF and UDP ownership fixes. Its candidate has the production implementation in `6f1626640d733e4f663b47f138f9881b5c557969`, before the final buffer growth adjustment. Both proxy endpoints were changed in this local comparison; the CI comparison instead keeps the base client fixed and changes only the server.

## Completed local checks

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --locked --all-targets --all-features -- -D warnings`: passed.
- `cargo test --workspace --locked --all-features`, with `SNELL_RS_TEST_BIN` pointing to the built candidate executable: passed, 249 unit/integration tests and one compile-fail doctest on Linux. This includes 123 protocol tests, 86 runtime tests and all three process-oracle tests.
- `cargo build --release --locked -p snell`: passed.
- All six existing benchmark executables completed: runtime `tcp_loopback`, `reuse_loopback`, `udp_loopback`, `kdf_bound`; protocol `v4_record`, `v6_record`.

`cargo test` was used rather than nextest. Local deny, Miri, AddressSanitizer and libFuzzer execution are not included in these local results; their executions are separate GitHub Actions checks. A successful earlier CI revision is not evidence that a later revision passed.

## Local isolated comparison

Five alternating runs per variant, five-second measurement windows, no concurrent compilation. Values are medians. RSS is server resident memory, not the sum of all processes or buffer capacities. Mixed traffic uses eight bulk connections plus small-message latency sampling.

| Scenario | Baseline | Candidate | Unit |
| --- | ---: | ---: | --- |
| v4 download | 1294.660 | 1266.653 | MiB/s |
| v4 upload | 1238.852 | 1246.328 | MiB/s |
| v4 mixed | 1867.768 | 1940.304 | MiB/s |
| v4 mixed CPU | 0.726 | 0.698 | CPU seconds/GiB |
| v4 mixed p99 | 37.200 | 33.868 | ms |
| v4 authenticated idle, 100 connections | 6844 | 5536 | RSS KiB |
| v4 cold process | 3752 | 3948 | RSS KiB |
| v4 reuse churn p99 | 1.108 | 1.030 | ms |
| v6 shaped download | 1168.077 | 1179.304 | MiB/s |
| v6 shaped mixed | 1942.811 | 1897.477 | MiB/s |
| v6 shaped mixed p99 | 28.296 | 32.107 | ms |
| v6 unshaped download | 1263.243 | 1294.219 | MiB/s |

These observations are mixed, not a claim of universal acceleration. In particular, the measured v6 shaped mixed p99 increased about 13.5%. The short local windows do not establish statistical significance or WAN behavior. The memory result for 100 idle v4 connections is approximately a 19.1% lower total RSS; the slightly larger cold footprint is reported separately rather than hidden.

## Final allocation-step ablation

Five alternating three-second mixed-traffic runs compare the implementation above with the final growth adjustment: when a geometric allocation would already exceed half the hard limit, allocate the hard limit directly. This skips the near-identical 64 KiB to 67 KiB reallocation without changing the legal record size or initial allocation.

| Protocol | Before MiB/s | After MiB/s | Before RSS KiB | After RSS KiB | Before p99 ms | After p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| v4 | 1868.705 | 1844.418 | 5624 | 5220 | 34.689 | 34.686 |
| v6 shaped | 1998.217 | 1989.848 | 5672 | 5184 | 27.844 | 29.193 |
| v6 unshaped | 1828.053 | 1799.195 | 5540 | 5288 | 36.340 | 36.175 |

The adjustment reduced active RSS in this experiment by 252-488 KiB, with throughput differences within 1.6%. It is an allocation/retention tradeoff, not a demonstrated throughput improvement. The pointer-stability regression also verifies that growing an occupied 40,000-byte buffer to its legal maximum does not allocate again.

## Protocol and failure-path evidence

The regression suite covers initialized-buffer boundaries, cancellation rollback, bounded partial reads, idle shrinking with live bytes, absolute handshake deadlines, admission recovery, active reuse expiry, early zero-chunk followed by a pipelined CONNECT, packet/control cancellation and failed sends. A controlled slow-DNS test verifies that the reverse UDP direction and idle timeout remain live.

Thirty-two PSK/profile variants verify that cancelled v6 reservations preserve subsequent wire bytes. The actual profile chunk limit never exceeds 16,383 bytes, so increasing the runtime read hint does not increase record payload in this implementation. No additional hint configuration or changed wire limit was introduced.

The early-payload bound is tested with all input deterministically ready, at exactly 64 KiB and at 64 KiB plus one. A real socket may return Pending between segments; subsequent data belongs to steady relay rather than an arbitrarily extended early-prefetch window.

The Performance workflow builds base and head with identical settings, uses a fixed base client, and saves environment metadata plus five alternating ten-second runs for each scenario as JSONL artifacts. Benchmark completion and performance improvement are separate facts; the raw values, including regressions, determine the latter.

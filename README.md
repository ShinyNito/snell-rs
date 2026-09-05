# snell-rs

Rust Snell TCP/UDP client and server. The synchronous `snell-protocol` crate
contains the wire codecs; `snell-runtime` owns sockets and bounded tasks.

## Run

```sh
cargo build --release --locked -p snell
target/release/snell-rs server --config server.conf
target/release/snell-rs client --config client.conf
```

```ini
[snell-server]
listen = 0.0.0.0:8443
psk = replace-with-your-own-secret
version = 6
max_connections = 1024
max_handshakes = 64
```

```ini
[snell-client]
listen = 127.0.0.1:1080
server = 127.0.0.1:8443
psk = replace-with-your-own-secret
version = v6-default
reuse = true
max_connections = 1024
max_handshakes = 64
```

Omit the server `version` to detect v4/v5 and v6-default. Explicit v6
`mode = unshaped` pairs with client `version = v6-unshaped`.
Client v4 and v5 are selected with `version = v4` and `version = v5`.

`max_connections` bounds all accepted session tasks, including idle reuse
connections. `max_handshakes` separately bounds unauthenticated/setup work.
Both must be positive; their defaults are shown above. Excess connections are
closed before spawning a task. A single 15-second deadline covers setup,
including KDF admission and outbound connection establishment. Shutdown cancels
and joins owned session tasks.

TCP buffers allocate on demand up to the unchanged legal wire limit. An idle
reused server connection releases empty encode storage and shrinks receive
storage after a 100 ms grace period; pipelined live bytes are preserved. The
client reuse pool expires entries even without a subsequent checkout.

## Checks

```sh
cargo xtask check
cargo test --workspace --locked --all-features
SNELL_RS_TEST_BIN="$PWD/target/release/snell-rs" cargo test --locked -p snell-testkit --test process_oracle
```

`xtask check` runs fmt, Clippy, tests and cargo-deny. It uses cargo-nextest when
installed, otherwise cargo test. CI additionally runs bounded decoder and
round-trip fuzz targets, Miri on buffer/platform boundaries, and AddressSanitizer.

Protocol buffers and record reservations implement `bytes::BufMut`. Safe
`put_slice` and the runtime I/O adapter track initialized bytes. There is no safe
bare-length operation that exposes uninitialized payload as initialized data.
The protocol crate does not depend on Tokio.

## Measurements

```sh
cargo bench --locked -p snell-runtime --bench tcp_loopback
cargo bench --locked -p snell-runtime --bench reuse_loopback
cargo bench --locked -p snell-runtime --bench udp_loopback
cargo bench --locked -p snell-runtime --bench kdf_bound
python3 scripts/bench_isolated.py --binary target/release/snell-rs --mode download
python3 scripts/bench_isolated.py --binary target/release/snell-rs --mode mixed --connections 8
python3 scripts/bench_isolated.py --binary target/release/snell-rs --baseline /path/to/baseline --mode idle --connections 100
```

The Python standard-library harness runs target, client and server in separate
processes, alternates baseline/candidate order, and emits JSONL. On Linux it
records server CPU, RSS/PSS, private/anonymous memory, threads and file
descriptors separately from the traffic generator. Modes include upload,
download, duplex, mixed small-message/bulk traffic, idle connections and churn.
Use `--reuse`, `--version 6`, `--unshaped`, `--client-binary`, `--workers`,
`--seconds` and `--repeat` to select a reproducible workload. The default
measurement window is 30 seconds with five repeats. Do not run compilers or
other CPU-heavy jobs alongside measurements.

Capacity is not RSS; allocator-retained pages and kernel socket memory are
separate costs. Loopback throughput and latency do not describe a WAN link.
PGO release builds and portable CPU variants are produced by the existing
release workflow; worker count can be controlled with `TOKIO_WORKER_THREADS`.

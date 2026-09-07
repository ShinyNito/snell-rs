# Project

This repository is a Rust implementation of the Snell protocol.
All crates stay unpublished (`publish = false`).

# Non-negotiable rules

- Preserve wire behavior covered by `tests/golden/` and protocol/interop tests.
- Complete the scope agreed in the task; do not infer phases from missing documents.
- Do not add speculative abstractions.
- Do not use unsafe outside the approved buffer/platform modules.
- Do not add unbounded queues, maps, pools, tasks, or buffers.
- Do not claim a performance improvement without benchmark evidence.
- Do not use channels in the TCP per-connection data path.
- Do not use trait objects or boxed futures in steady-state record processing.
- Do not log secrets.
- Peer-controlled input must never panic.
- Do not publish crates to crates.io.

# Architecture boundaries

- snell-protocol is synchronous and runtime-free.
- snell-runtime owns Tokio, sockets, tasks, timeouts, UDP, reuse, outbound, and platform socket options.
- snell-config converts raw text into validated runtime configuration.
- snell is the binary composition root.
- snell-testkit and xtask are development-only.

# Required commands

Run before finishing implementation:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build -p snell --all-features
SNELL_RS_TEST_BIN="$PWD/target/debug/snell-rs" cargo nextest run --workspace --all-features --run-ignored all
cargo deny check
```

If `cargo nextest` is unavailable, `cargo test --workspace --all-features` is
the fallback (with `-- --include-ignored` and the same binary environment).
`cargo xtask check` runs fmt, clippy, builds the process-test binary, runs tests
including the process oracle and doctests, then deny. It uses nextest when
available and falls back to cargo test only when nextest is unavailable.
For a custom target directory, adjust `SNELL_RS_TEST_BIN` accordingly.

Run golden, interop, Miri, sanitizer, and benchmark checks relevant to the change.
Report missing external differential binaries or fuzz harnesses as unrun checks.

# Change discipline

Before editing:

1. Read applicable repository guidance and the task's referenced plans.
2. Inspect the affected code and callers before changing their contracts.
3. State the invariant being implemented.
4. Add or update the failing test first where practical.
5. Implement the smallest complete solution.
6. Run all gates.
7. Report exact commands and results.

Do not leave placeholder implementations, silent fallbacks, or fake metrics.

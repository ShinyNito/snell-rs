# Project

This repository is a Rust implementation of the Snell protocol.
All crates stay unpublished (`publish = false`).

# Non-negotiable rules

- Preserve verified wire behavior documented in `docs/PROTOCOL.md`.
- Complete only the current phase in docs/PLAN.md.
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

Run before finishing every phase:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo deny check
```

If `cargo nextest` is unavailable, `cargo test --workspace --all-features` is
the fallback. `xtask check` runs fmt, clippy, test, and deny.

Run phase-specific golden, differential, interop, fuzz, Miri, sanitizer, and
benchmark commands documented in that phase.

# Change discipline

Before editing:

1. Read REQUIREMENTS.md, PROTOCOL.md, ARCHITECTURE.md, and the current phase.
2. Inspect the existing code in this repository completely.
3. State the invariant being implemented.
4. Add or update the failing test first where practical.
5. Implement the smallest complete solution.
6. Run all gates.
7. Report exact commands and results.

Do not leave placeholder implementations, silent fallbacks, or fake metrics.

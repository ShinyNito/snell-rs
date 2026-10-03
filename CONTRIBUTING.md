# Contributing

Read [AGENTS.md](AGENTS.md) first: it lists the rules every change keeps
(wire compatibility, where `unsafe` may live, bounded resources) and the
commands to run before sending a change.

## Structure

The repository is a Cargo workspace. Each crate owns one layer, and lower
layers never depend on higher ones.

```
crates
├── snell-protocol      Synchronous protocol kernel: no I/O, no async runtime
│   └── src
│       ├── codec       Record codecs and the RecordEncoder/RecordDecoder traits
│       │   ├── v4      v4/v5 records: chunk window, initial padding
│       │   └── v6      v6 shaped, unshaped, and unsafe-raw records
│       │       └── profile   PSK-derived traffic shaping
│       ├── control     CONNECT, UDP setup, server replies, UDP datagrams
│       ├── crypto      PSK, Argon2id key derivation, AES-128-GCM, nonces, entropy
│       ├── buffer.rs   Buffer and Reservation (the crate's only unsafe code)
│       ├── socks5.rs   SOCKS5 messages
│       └── address.rs, parse.rs, error.rs
├── snell-runtime       Tokio runtime: sockets, tasks, timeouts, UDP, reuse
│   └── src
│       ├── client      Local SOCKS5 proxy, connection pool, UDP relay
│       ├── server      Snell server, protocol auto-detection, outbound, UDP associations
│       ├── platform    Socket options per OS (unsafe allowed)
│       ├── session.rs  Record I/O shared by client and server
│       ├── buffer.rs   Pooled session buffers (unsafe allowed)
│       ├── bufio.rs    Socket reads into leased buffers (unsafe allowed)
│       └── codec.rs, kdf.rs, replay.rs, dns.rs, udp.rs, error.rs
├── snell-config        INI and command-line parsing into validated configuration
├── snell               The snell-rs binary
└── snell-testkit       Golden fixtures, process tests, shared test helpers
examples                Example INI files, parsed by snell-config's tests
tests/golden            Wire fixtures checked against the codecs
xtask                   `cargo xtask check`: every required gate in one command
```

A directory module keeps its interface in `mod.rs` and its parts in sibling
files. Tests live next to the code they cover; behavior shared by every codec
runs once per codec in `snell-testkit/tests/codecs.rs`.

## Checks

`cargo xtask check` runs formatting, clippy, the tests (including process
tests and doctests), and `cargo deny`. Changes to unsafe code also run Miri on
the affected module, for example:

```bash
cargo +nightly miri test -p snell-protocol --all-features --lib buffer::
```

Performance claims need numbers from the benches in `crates/*/benches`, run
against the previous release on the same machine.

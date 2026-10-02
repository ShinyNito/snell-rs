# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

Performance-first review cleanup. No protocol, wire format, or configuration-file changes: golden fixtures and the v6 padding-generator corpus hashes are byte-identical.

### Performance
- v6 shaped padding generators no longer divide by a runtime value for every byte. Generator 0 maps eight bytes per step through its table rows, generator 1 uses a byte-width reciprocal and a branch-free choice, generator 2 byte-width arithmetic, and generator 3 writes each period as one run over a pre-repeated motif. `profile::bench::fill_baseline`, median for a 1460-byte fill against 0.1.2 built and run back to back: generator 0 603 → 564 ns, generator 1 9.65 → 1.31 µs, generator 2 2.03 → 0.54 µs, generator 3 6.15 → 0.60 µs; outputs are identical. End to end on the same 4-CPU host: `v6_record` encode+decode of 64-byte shaped records is 3.6–4.3× faster for generator 1, 3.2–3.9× for generator 3 and 1.7–2.0× for generator 2; `tcp_loopback` v6-shaped 64-byte ping-pong p50 went from 71–73 µs to 57 µs; `udp_loopback` v6-shaped burst from 744–746 ms to 406–438 ms. v4 and v6-unshaped stayed within run-to-run noise in interleaved reruns.
- Per-connection memory is lower. Server and client configuration is shared through one `Arc` instead of cloned into every task; a `Psk` derives its v6 shaping profile once and shares it with every codec built from it; setup state (protocol auto-detection, client dial and CONNECT) lives in a boxed future that is freed once the tunnel is open; and session futures own each socket and codec once instead of holding by-value copies across awaits. With `-Zprint-type-sizes`, the spawned server session future went from 15,968 to 4,304 bytes, the client session from 14,784 to 3,760, a client UDP association from 4,960 to 3,440, and a v6-shaped encoder/decoder pair from 2,240 to 1,280. `staggered_tunnel` with 256 idle-heavy connections, two interleaved runs per build: mean RSS 10.8 → 7.1 MiB for the client and 9.7–10.6 → 6.9–7.2 MiB for the server, with throughput and burst latency unchanged.
- Record sealing commits capacity the reservation already holds instead of re-validating it per record, and record headers are built infallibly from encoder-bounded lengths. The v6 shaped decoder authenticates the record prefix in place as AAD instead of copying it with the header.
- Upstream SOCKS5 UDP sends the header and the borrowed payload as one vectored datagram, like the client response path, instead of repacking them through a leased buffer.

### Changed
- Encoders track one lifecycle state (ready, reserving, poisoned) instead of separate `reserving`, `poisoned`, and per-reservation `sealed` flags. The v4 chunk window is one `Option` instead of a salt flag, a zero sentinel, and a timestamp; the v6 shaped encoder derives "salt sent" from its last-write time; v6 decoders keep the cipher and its salt (the replay identity) in one `Option`.
- `V6UnshapedEncoder` has no type parameters and `V6ShapedEncoder` only its clock: the unused entropy/clock generics are gone. `Clock::unix_secs` was never read and is removed; `UnixClock` is now `MonotonicClock`.
- The unsafe-raw encoder keeps per-record layout in its reservation instead of encoder fields.
- SOCKS5 address fields are validated in one pass; Snell and SOCKS5 parsers share the IP and domain tail readers; encoders share one destination-capacity check.
- `snell_runtime::ClientConfig` enables reuse through `pool: Some(_)` alone; the separate `reuse` flag is removed.
- The KDF wait queue and the SOCKS5 UDP control limit are Tokio semaphores instead of hand-rolled counters and drop guards; the server UDP association limit is one atomic `try_update`.
- `snell-config` returns the runtime's `Outbound` and `TcpBrutal` instead of duplicate types the binary had to convert.
- The accept loop's backoff handling is inlined into `AcceptLoop::next`; TCP Fast Open and tcp-brutal share one `setsockopt` helper.
- Server exact-flavor sessions share one setup path parameterized by codec constructors; the client opens tunnels through one `establish` step that tries a pooled connection and falls back to a fresh dial. Pooled connections and the auto-detected codec use one `Codec` enum.
- The client UDP relay keeps its routing tables in one `Routes` value (association per peer, peers per control connection) and its shared handles in one `Relay`, instead of passing them separately to each task.

### Tests
- Codec behavior shared by v4, v6-unshaped, and v6-shaped (fragmentation, decode-ahead, zero chunks, tamper detection, cancellation, Debug redaction) runs once per codec in `snell-testkit`; `seal_init` parity runs once per codec in the buffer module. The per-codec copies are removed.
- SOCKS5 TCP/UDP test helpers live once in `snell-testkit::oracle`, built on the protocol crate's SOCKS5 codec, and replace copies in the runtime tests, binary tests, and benches. `ProcessPair` takes `ServerOptions`.
- Duplicate or tautological tests are removed, and process tests share one parametrized body.

## 0.1.2

Internal cleanup. No protocol, wire format, configuration, or CLI changes; golden fixtures are byte-identical.

### Changed
- Toolchain and MSRV are Rust 1.98.1.
- Record codecs share one AEAD seal/open helper (which advances the nonce), one decode-ahead accounting type, and one reservation slot. Per-record layout now lives in the reservation instead of stale encoder fields.
- PSK length is validated once, by `Psk`: `aead_key`, profile derivation and `V6ShapedDecoder::new` take `&Psk`/`Psk` and no longer re-check it; `V6ShapedDecoder::new` is infallible.
- Provably unreachable clamps and branches in v6 profile derivation, salt-block shuffling and padding mixing are removed.
- UDP request/response address encoding and decoding share one address-tail codec.
- The runtime KDF path clones the zeroizing `Psk` instead of copying it into a plain `Vec`.
- Plain encode batches are drained with Tokio's `write_all_buf` over `bytes::Buf::chain`; outbound SOCKS5 CONNECT and UDP ASSOCIATE share one negotiation; TCP Fast Open uses `libc` option constants; the replay cache stores each salt's timestamp once.
- Auto-detect reuses the server's first-request parser and the client's codec enum.
- Duplicated tests are merged: codec fragmentation cases run once per codec in `snell-testkit`, and golden fixtures are checked against the real encoders.

## 0.1.1

Internal optimization and build release. No protocol, wire format, configuration, or CLI changes; 0.1.0 clients and servers interoperate with 0.1.1 unchanged.

### Added
- mimalloc is the `snell-rs` binary's global allocator, behind a default-on `mimalloc` feature. Building with `--no-default-features` restores the system allocator for environments without a C toolchain. mimalloc's secure mode is off.

### Changed
- Shaped v6 records are sealed in place: the payload stays where the socket read placed it, and the salt block, record prefix, header and padding are written after it. Records are restored to wire order with vectored writes, removing the memmove that a padding-length change previously forced. Wire bytes are unchanged.
- SOCKS5 UDP responses send the header and the borrowed payload as one vectored datagram, so the response path no longer repacks them through an intermediate buffer.
- The generator0 byte table is computed at compile time into a shared PSK-independent static, replacing the per-call bit-fixup loop.
- Session buffer growth reuses a large-enough cached block from the pool before allocating a new size class.
- `Buffer::spare_capacity_mut` checks capacity before compacting, so a failed reservation no longer moves live bytes.

## 0.1.0

First release of `snell-rs`. All crates remain unpublished (`publish = false`). The distributed product is the `snell-rs` binary.

### Added
- **Protocol Support**:
  - Snell v4 with AES-128-GCM and Argon2id key derivation.
  - Snell v5 TCP proxying (uses the v4 record codec; v5 QUIC is out of scope).
  - Snell v6 default (shaped) with profile-driven salt block masking, record prefixes, and traffic shaping padding.
  - Snell v6 unshaped mode with zero padding (exact configuration required).
  - Server protocol auto-detection between v4 and v6-default when server version is omitted. (v6-unshaped requires exact configuration; v6-unsafe-raw is rejected by configuration and CLI).
- **Traffic Forwarding & Proxy Capabilities**:
  - Local SOCKS5 inbound proxy on client supporting TCP CONNECT and UDP ASSOCIATE.
  - Direct outbound connection support on server.
  - Upstream SOCKS5 proxy routing on server via `upstream_socks5` / `--socks5-outbound`.
- **Connection Management & Reuse**:
  - Single-shot TCP CONNECT (`CMD 0x01`).
  - TCP connection reuse (`CMD 0x05`, CONNECT_V2) and bounded client connection pooling (`reuse = true`, maximum 10 connections, 300-second idle timeout).
  - UDP datagram relay over Snell TCP (`CMD 0x06`) with per-association tracking and 300-second idle expiration.
- **Configuration & CLI**:
  - Subcommands `snell-rs client`, `snell-rs server`, and `snell-rs version`.
  - INI configuration file support via `--config` (`[snell-client]` and `[snell-server]`). Unknown keys are ignored.
  - Command-line argument support for client and server configurations.
  - Pre-shared key (PSK) validation enforcing raw UTF-8 string lengths between 16 and 255 bytes.
- **Platform & Socket Optimizations**:
  - TCP keepalive enabled across all session TCP connections (idle 300s, probe interval 75s) on Linux, macOS, and Windows.
  - Optional TCP Fast Open (TFO) support on Linux and macOS with safe fallback when unsupported.
  - Optional Linux TCP Brutal congestion control (`tcp_brutal = true`, `tcp_brutal_send_mbps`, `tcp_brutal_cwnd_gain`), applied per accepted connection. `tcp_brutal_send_mbps` / `tcp_brutal_cwnd_gain` without `tcp_brutal = true` are ignored, and an unusable kernel module or sockopt logs a warning instead of refusing to start.
  - Resource backoff handling for file descriptor limits (`EMFILE` / `ENFILE`).
- **Observability & Security**:
  - Structured logging via `tracing` with global `--log-level` flag and `RUST_LOG` environment variable override.
  - Zero-secret logging policy ensuring pre-shared keys, session keys, salts, nonces, and user payloads are never logged.
- **Performance**:
  - TCP sessions decode consecutive records ahead and flush them with one vectored write, keeping record order and wire behavior unchanged.
  - TCP record payload slots remain uninitialized until filled, avoiding redundant zeroing while preserving wire bytes.
  - UDP packet buffers are reused and processed in place, avoiding per-datagram copies and repeated buffer initialization.
  - Session buffers are leased from a sharded bounded cache and returned at empty I/O boundaries, so idle connections retain no backing storage.
- **Release Engineering**:
  - Release artifacts for x86-64 v2/v3/v4, linux ARM64, musl static, and Intel macOS, built with explicit CPU variants and release optimization settings.
  - Process-level TCP echo soak (`cargo xtask soak`, `SNELL_SOAK_SECS`), a version smoke test, and five example INI files covered by a config parsing test.

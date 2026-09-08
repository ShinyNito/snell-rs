# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

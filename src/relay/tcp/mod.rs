//! TCP 中继 driver：把 SOCKS5 入站连接桥接到 Snell 加密上游。
//!
//! 数据流（CONNECT 阶段）：
//!
//! ```text
//!  client                local driver                    snell server / remote
//!    │                        │                                  │
//!    │ ── socks5 greeting ──▶ │                                  │
//!    │ ◀── method NO_AUTH ─── │                                  │
//!    │ ── socks5 request  ──▶ │  parse dst (Address)             │
//!    │                        │                                  │
//!    │                        │ ── dial snell TCP ─────────────▶ │
//!    │                        │ ── Snell first record: ────────▶ │
//!    │                        │    salt + AEAD(ConnectCmd(dst))  │
//!    │                        │                                  │
//!    │                        │ ◀── Snell Tunnel / Error ─────── │
//!    │                        │                                  │
//!    │ ◀── socks5 reply ───── │  only after Tunnel               │
//!    │                        │  (Error / dial failure → reply   │
//!    │                        │   with mapped failure code)      │
//!    │                        │                                  │
//!    │ ═══ payload ═════════▶ │ ═══ Snell encrypted payload ═══▶ │
//!    │ ◀══ payload ═════════ │ ◀══ Snell encrypted payload ═══ │
//! ```
//!
//! 关键顺序：socks5 succeeded 必须等到 Snell 上游回 `Tunnel` 之后再写回；
//! 否则一旦上游回 `Error` 或 dial remote 失败，客户端会误以为 CONNECT 已建立。
//!
//! Snell 没有独立的握手帧——`ConnectCmd(dst)` 直接作为 record 层第一条
//! 加密 payload 发出，解密后的明文形如：
//!
//! ```text
//!  [0x01][Connect/ConnectV2][client_id_len][client_id][host_len][host][port]
//! ```
//!
//! 与 [`crate::protocol`] 下纯解析/编码模块的分工：本层只负责把字节在两端
//! 之间搬运，协议帧的解析、加密、地址编码全部交给 `protocol::socks5` 与
//! `protocol::snell` 中的无运行时 helper。

pub mod client;
pub mod driver;
pub mod handshake;
pub mod pool;
pub mod transport;

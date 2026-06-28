//! SOCKS5 handshake (control plane) — async fn.
//!
//! SOCKS5 handshake 是一次性、小字节、顺序控制面：read greeting → write
//! method → read CONNECT request。这里用 `async fn` + `read_exact`/`write_all`，
//! 让编译器生成状态机，不手写 `poll` + `enum State`。手写 poll 状态机留给
//! 真正的热路径数据面（`TcpTunnelDriver`，established 后双向 relay）。
//!
//! ## 不读多（关键约束）
//!
//! 每一步用精确字节数的 `read_exact(n)`，只读协议要求的字节，绝不把控制头
//! 之后的客户端应用 payload（ClientHello 等）吞进控制面 buffer——那些必须
//! 留给后续 Snell encoder slot 原地读取。`request_need`/`greeting_need` 的
//! `Need(total)` 驱动每次读多少。
//!
//! ## 时序（来自 `tcp/mod.rs` 文档）
//!
//! SOCKS5 Succeeded **不在这里写**——它必须等 Snell 上游回 Tunnel 之后才写
//! （否则上游 Error/dial 失败时客户端误以为 CONNECT 已建立）。本模块只到
//! 拿到 target 为止；dial/ConnectCmd/WaitTunnel/Succeeded 在后续阶段。

use compio::{buf::IoBuf, io::AsyncWriteExt, net::TcpStream};

use crate::protocol::address::Address;
use crate::protocol::socks5::{self, Command, METHOD_NO_AUTH, ParseState, Socks5Error};

use super::driver::read_exact_managed;

/// SOCKS5 握手错误。由调用方负责写对应 SOCKS5 错误回复（或关闭）。
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("socks5 protocol error: {0}")]
    Protocol(#[from] Socks5Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("client offered no acceptable auth method")]
    NoAcceptableMethod,
    #[error("unsupported SOCKS5 command: {0:?}")]
    UnsupportedCommand(Command),
    /// Snell 上游阶段失败（dial / ConnectCmd / Tunnel Error）。
    /// 具体错误类型等 frame codec 落地后补。
    #[error("snell upstream error: {0}")]
    Snell(String),
}

/// 接受一个 SOCKS5 CONNECT：greeting → method → request，返回目标地址。
///
/// 到此为止——控制头已消费，剩下的字节是客户端应用 payload。Snell dial /
/// ConnectCmd / WaitTunnel / SOCKS5 Succeeded 在调用方后续阶段处理。
pub async fn accept_socks5_connect(local: &mut TcpStream) -> Result<Address, HandshakeError> {
    let (command, destination) = accept_socks5_request(local).await?;
    if !matches!(command, Command::Connect) {
        return Err(HandshakeError::UnsupportedCommand(command));
    }
    Ok(destination)
}

pub async fn accept_socks5_request(
    local: &mut TcpStream,
) -> Result<(Command, Address), HandshakeError> {
    // read_greeting 内部确认客户端支持 no-auth，否则报 NoAcceptableMethod。
    read_greeting(local).await?;
    write_method_selection(local).await?;
    read_request(local).await
}

/// 读客户端 greeting（`VER NMETHODS METHODS`），确认支持 no-auth。
/// 不支持则报 `NoAcceptableMethod`（调用方负责写 no-acceptable 回复或关闭）。
async fn read_greeting(local: &mut TcpStream) -> Result<(), HandshakeError> {
    let mut buf = [0u8; 2 + 255]; // VER + NMETHODS + METHODS(max 255)
    let mut filled = 0;
    let greeting = loop {
        let need = match socks5::greeting_need(&buf[..filled]) {
            Ok(ParseState::Done(g)) => break g,
            Ok(ParseState::Need(total)) => total,
            Err(e) => return Err(e.into()),
        };
        if need > buf.len() {
            return Err(Socks5Error::Malformed("oversized greeting").into());
        }
        if filled < need {
            read_exact_into(local, &mut buf[filled..need]).await?;
            filled = need;
        }
    };
    if !greeting.supports(METHOD_NO_AUTH) {
        return Err(HandshakeError::NoAcceptableMethod);
    }
    Ok(())
}

/// 写服务端 method selection（`VER METHOD = NO_AUTH`）。
///
/// 前置：`read_greeting` 已确认客户端支持 no-auth。
async fn write_method_selection(local: &mut TcpStream) -> Result<(), HandshakeError> {
    let mut reply = [0u8; 2];
    let n = socks5::encode_method_selection(&mut reply, METHOD_NO_AUTH)?;
    let (result, _reply) = local.write_all(reply.slice(..n)).await.into_parts();
    result?;
    Ok(())
}

/// 读客户端 request（`VER CMD RSV ATYP DST.ADDR DST.PORT`），返回
/// `(command, destination)`。返回值在函数内从局部 buf 提取，不借用 buf，
/// 调用方可以安全持有。
async fn read_request(local: &mut TcpStream) -> Result<(Command, Address), HandshakeError> {
    let mut buf = [0u8; 3 + 1 + 1 + 255 + 2]; // VER CMD RSV + addr field max
    let mut filled = 0;
    let request = loop {
        let need = match socks5::request_need(&buf[..filled]) {
            Ok(ParseState::Done(r)) => break r,
            Ok(ParseState::Need(total)) => total,
            Err(e) => return Err(e.into()),
        };
        if need > buf.len() {
            return Err(Socks5Error::Malformed("oversized request").into());
        }
        if filled < need {
            read_exact_into(local, &mut buf[filled..need]).await?;
            filled = need;
        }
    };
    // request.destination 借用 buf，但 buf 是局部——返回 owned 形态避免悬空。
    Ok((request.command, request.destination.into_owned()))
}

async fn read_exact_into(stream: &mut TcpStream, dst: &mut [u8]) -> std::io::Result<()> {
    read_exact_managed(stream, dst).await
}

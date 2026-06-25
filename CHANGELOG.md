# Changelog

## [0.1.3] - 2026-06-25

## Release Notes

  * 新增服务端 tcp_brutal 配置，支持设置发送速率与 cwnd_gain，并在不支持的平台或内核能力缺失时提前报错。
  * 优化运行时日志，补充入站、出站、UDP 关联与探测失败等关键路径信息，便于排查连接问题。
  * 启用 mimalloc 与 release 编译优化，降低运行时分配开销并减小发布构建体积。

## [0.1.2] - 2026-06-25

## Release Notes

  * 为客户端、服务端入站与 TCP outbound 启用 TCP keepalive，降低长连接静默断开的影响。
  * 修复复用 TCP 子流空闲后未及时清理的问题，复用连接在等待下一条请求超时后会主动结束。
  * 修复 UDP outbound 发送暂挂时明文帧可能丢失的问题，避免待发送 UDP 数据报被跳过。

## [0.1.1] - 2026-06-24

## Release Notes

  * 新增 GitHub CI 与 Release 工作流，支持三平台验证、多目标构建、校验和与 GitHub Release 发布。
  * 接入 clap 子命令与 INI/CLI 双入口，client/server 可以通过配置文件或命令行启动。
  * 实现 Snell 客户端与服务端 TCP 入站，支持 SOCKS5 入站、Direct/SOCKS5 outbound 与 v4/v5/v6 自动探测。
  * 实现 TCP/UDP 中继层，包括 poll-based TCP relay、UDP NAT 表、SOCKS5 UDP ASSOCIATE 与连接复用。
  * 集成 SOCKS5 与 Snell v4/v6 协议编解码，覆盖 shaped、unshaped、unsafe-raw、地址、KDF、profile 与 salt 逻辑。
  * 切换到 tokio 运行时，并补齐 TCP connect/read 超时基础设施。

## [0.1.0] - 2026-06-24

- Added Snell client and server command-line entry points.
- Added Snell TCP relay, UDP relay, SOCKS5 inbound, and SOCKS5 outbound paths.
- Added protocol, relay, timeout, and config tests for the current implementation.

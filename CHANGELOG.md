# Changelog

All notable changes to this project are maintained manually.

## [0.4.7] - 2026-06-15

## Release Notes

  * socks5 connect 在服务端 tunnel reply 返回后再回 success：服务端报错时按 snell v6 错误码、IO error kind、DNS 错误映射到对应的 SocksReply（新增 NetworkUnreachable / HostUnreachable / ConnectionRefused / TtlExpired），不再一律 GeneralFailure；read_client_request 对不支持命令、地址类型与空域名也返回具体 reply
  * UDP 关联改为复用上游 socks5 会话：控制连接关闭或空闲超时仅关闭当前关联，下一条消息到达时重新打开，不再结束整条 snell 会话
  * 收敛多处局部 buffer 到 `Box<struct>` 降低栈分配；拆分 lazy quic UDP relay 的接收首包 / snell 路径 / quic-proxy 主循环为三个职责函数
  * 修复 Linux 上 UDP relay 因 `recvmmsg` 裸调未消费 tokio 可读标记导致 select 饥饿、关联无法正常关闭的问题：`try_recv_from` 改用 `socket.try_io(Interest::READABLE, ...)` 正确清除 readiness

## [0.4.6] - 2026-06-14

## Release Notes

  * UDP 关联移除服务端空闲超时轮询，改由传输层 EOF 关闭；framed reader 在干净帧边界（decoder 已初始化、无 pending header、body 空）收到 `UnexpectedEof` 时返回 `Ok(None)`，不再误报错误
  * protocol 构造函数用语义明确的 `#[must_use]` 替代 `#[allow(clippy::must_use_candidate)]` 压制

## [0.4.5] - 2026-06-14

## Release Notes

  * 统一 TCP 中继和活动超时编排，复用连接、客户端/服务端 relay 与测试辅助代码改用共享的会话状态路径，减少重复生命周期处理
  * 收紧协议长度字段、FFI 参数和 v4/v6 profile 派生中的窄化转换，避免依赖隐式 `as` 截断；保留协议低位混洗语义并补充边界表达
  * 补充公开 `Result` API 的 `# Errors` 文档，并清理 `cargo clippy -- -W clippy::pedantic` 告警

## [0.4.4] - 2026-06-14

## Release Notes

  * v4 对齐官方 message-level 分块：大消息按 RecordSizer 的 chunk_limit 切成多个 record 聚合输出，reader 新增跨 record 重组，30s idle reset 阈值与官方一致
  * Linux UDP 收发改用 recvmmsg/sendmmsg（cap 20，scatter/gather），对齐官方 libuv 批量路径；非 Linux 保留单 datagram 回退
  * 提取共享的 payload 编码与 UDP/会话中继逻辑：v4/v6 写路径经 MessageRecordEncoder 合并，TcpClient/TcpServer/Reuse 复用统一的 plain batch 填充与写入，两个 socks5 UDP relay 合并为参数化函数

## [0.4.3] - 2026-06-14

## Release Notes

  * framed writer 改为批量预读后合并帧写入，将多条 record 的密文累积到单次 write，降低写热路径 syscall 开销
  * v4/v6 帧编码新增 `encode_payload_parts_into`，并补充 reference/message 双路径逐字节等价回归测试，清理被取代的 `write_test_*` 测试桩

## [0.4.2] - 2026-06-14

## Release Notes

  * 改用 poll 读取接口并引入预读/缓冲复用，降低协议帧读写热路径开销
  * 收紧 crate 公共 API 表面，并将大模块测试拆分到就近的 `tests.rs`
  * 补充 v4/v6 帧读写、复用连接、TCP/UDP 会话和 QUIC proxy 回归测试

## [0.4.1] - 2026-06-13

## Release Notes

  * 对齐当前 b2 版本协议派生、填充和 chunk/write 目标行为
  * 补充协议 golden 与 target padding cap 回归测试

## [0.4.0] - 2026-06-12

## Release Notes

  * 支持 Snell v6 协议
  * 重组协议、代理、会话和服务端模块，拆分配置与帧读写逻辑
  * 增加跨平台编译检查，并上传编译产物供下载

## [0.3.7] - 2026-06-11

## Release Notes

  * 全链路 payload 零拷贝重构：UDP 收包→就地 reframing→就地加密→scatter-gather 发送
  * V4FrameEncoder 改为 head/payload 分离的就地加密 API，移除冗余拷贝路径
  * V4StreamWriter 使用 poll_write_vectored scatter-gather 写入
  * 新增 udp_io 模块，SOCKS5→Snell 协议就地头部重构
  * Padding 算法优化为 O(target_bits) 的直接采样插入

## [0.3.6] - 2026-06-11

## Release Notes

  * 添加实例级 DNS 解析器，支持服务端配置独立 DNS 并避免全局解析状态互相覆盖
  * 优化 UDP 与 QUIC proxy 热路径，降低阻塞与重复解析开销
  * 添加 UDP loopback benchmark 和 DNS 实例隔离回归测试

## [0.3.5] - 2026-06-10

## Release Notes

  * 添加 release profile（LTO thin、codegen-units=1、strip、panic=abort），减小体积并提升运行性能
  * 提升服务端监听 backlog 至 4096，改善高并发握手吞吐
  * PSK 共享改用 Arc<Zeroizing> 避免重复拷贝
  * 扩展连接关闭错误识别，覆盖更多断连场景
  * 精简协议与中继热路径（容量预分配、Range 切片、迭代器化、消除重复逻辑）

## [0.3.4] - 2026-06-09

## Release Notes

  * 优化 v4 解密、随机源和缓冲区热路径

## [0.3.3] - 2026-06-09

## Release Notes

  * 优化复用连接的流缓冲区保留策略，减少大流量场景下的重复扩容

## [0.3.2] - 2026-06-09

## Release Notes

  * 使用 ring 加速 AES-GCM

## [0.3.1] - 2026-06-09

## Release Notes

  * 修复 loopback benchmark 的 clippy 检查

## [0.3.0] - 2026-06-09

## Release Notes

  * 添加服务端 server-side fast-open，在上游连接完成前先返回 Tunnel OK 并缓存早到 TCP payload
  * 添加协议和 loopback benchmark

## [0.2.3] - 2026-06-08

## Release Notes

  * 修复服务端复用连接在上游先关闭时的释放

## [0.2.2] - 2026-06-08

## Release Notes

  * 修复连接生命周期清理与复用连接关闭

## [0.2.1] - 2026-06-08

## Release Notes

  * Fixes and improvements

## [0.2.0] - 2026-06-08

## Release Notes

  * 集成服务端 TCP Brutal

## [0.1.0] - 2026-06-06

## Release Notes

  * 添加版本命令
  * Fixes and improvements

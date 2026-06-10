# Changelog

All notable changes to this project are generated from Conventional Commits.

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

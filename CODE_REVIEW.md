# 代码深度审查报告

## 严重问题 🔴

### 1. SSH Session 资源泄漏 (ssh.rs:171-384)
**位置**: `SshSession` 结构体
**问题**:
- `SshSession` 创建了后台任务 `reader_task`（第 285 行）
- 如果 `SshSession` 被 drop 而没有调用 `close()`，后台任务会继续运行
- 会导致 SSH 连接和 channel 资源泄漏

**影响**: 内存泄漏、SSH 连接泄漏
**修复**: 实现 `Drop` trait 确保 cleanup

### 2. SSH 主机密钥验证不安全 (ssh.rs:207-212)
**位置**: `ClientHandler::check_server_key`
**问题**:
- 当服务器密钥不在 known_hosts 时，代码接受连接并仅打印警告
- 这使得 MITM 攻击成为可能

```rust
warn!("Server key not found in known_hosts - accepting anyway");
Ok(true)  // 危险！
```

**影响**: 安全漏洞，可能遭受中间人攻击
**修复**: 应该拒绝连接或要求用户确认

### 3. WebSocket 异常退出时资源泄漏 (main.rs:350-563)
**位置**: `handle_terminal_socket`
**问题**:
- WebSocket 因错误退出时（第 529、533 行），SSH session 可能没有被正确清理
- 虽然第 556 行有 cleanup 代码，但如果在 cleanup 过程中出错，资源仍会泄漏
- 第 557 行：`session.close().await` 失败时只记录日志，SSH 连接保持打开

**影响**: SSH 连接泄漏、文件描述符泄漏
**修复**: 确保 cleanup 在错误时仍然执行

## 高优先级问题 🟠

### 4. SSH Reader Task 锁持有时间过长 (ssh.rs:287-315)
**位置**: `SshSession::connect` 的 reader task
**问题**:
- 第 287 行获取 `channel` 的 Mutex 锁
- 第 288 行在持有锁的情况下调用 `timeout(..., guard.wait()).await`
- 这会阻塞其他操作（write, resize, close）长达 50ms

**影响**: 性能问题，操作延迟
**修复**: 缩短锁的持有时间，只在必要时持有锁

### 5. 审计日志写入失败被忽略 (audit.rs:42-57)
**位置**: `AuditLogger::write_event`
**问题**:
- 审计日志写入失败时，调用者只能记录错误，不会阻止操作
- `log_connection` 和 `log_disconnection` 失败时只记录日志（main.rs:447, 551）
- 审计记录可能丢失

**影响**: 合规性问题，审计日志不完整
**修复**: 考虑在审计失败时阻止连接或使用更可靠的日志机制

### 6. SSH 输出 channel 缓冲区大小固定 (ssh.rs:280)
**位置**: `SshSession::connect`
**问题**:
- `mpsc::channel(64)` 只能缓冲 64 条消息
- 如果 SSH 输出速度 > WebSocket 发送速度，会阻塞 reader task
- 可能导致 SSH 连接停滞

**影响**: 性能瓶颈
**修复**: 使用更大的缓冲区或动态调整

### 7. 信号处理缺失 (main.rs)
**位置**: `main` 函数
**问题**:
- 没有 SIGTERM/SIGINT 信号处理
- 程序被 kill 时，正在进行的审计日志可能不完整
- SSH 连接不会被优雅关闭

**影响**: 资源泄漏、数据丢失
**修复**: 添加信号处理器进行优雅关闭

## 中优先级问题 🟡

### 8. WebSocket 轮询效率低 (main.rs:539)
**位置**: `handle_terminal_socket` 的 select!
**问题**:
- 每 10ms 轮询一次 SSH 输出，即使没有数据
- CPU 浪费，延迟不必要

**影响**: 性能问题
**修复**: 使用事件驱动机制

### 9. 错误处理不一致 (多处)
**问题**:
- SSH resize 失败只记录 debug 日志（main.rs:490）
- 审计日志失败后继续执行（main.rs:447）
- 某些错误被忽略，某些导致 panic

**影响**: 难以调试，错误状态不一致
**修复**: 统一错误处理策略

### 10. TLS listener 转换可能失败 (main.rs:138)
**位置**: `from_tcp_rustls(listener.into_std()?, ...)`
**问题**:
- `listener.into_std()` 可能失败（虽然概率低）
- 如果失败，程序直接退出

**影响**: 服务不可用
**修复**: 添加错误处理和重试机制

### 11. JWT Secret 生成后不可恢复 (auth.rs:21-27)
**位置**: `AuthService::new`
**问题**:
- 如果没有提供 JWT secret，会生成随机值
- 程序重启后，之前的 token 全部失效
- 所有用户需要重新登录

**影响**: 用户体验差
**修复**: 应该要求必须提供 secret 或持久化

## 低优先级问题 🟢

### 12. SSH 配置解析不支持多行 Host (ssh.rs:51-137)
**问题**: SSH 配置支持 Host 指令有多个模式（如 `Host *.example.com`），但代码只取第一个

### 13. 静态文件路径安全检查不完整 (main.rs:234-238)
**问题**: 只检查 `..`、`\` 和开头 `/`，但没有检查 URL 编码的路径遍历

### 14. 审计日志格式缺少字段 (audit.rs:12-26)
**问题**: 没有记录源 IP、用户代理、操作结果等关键信息

### 15. WebSocket 输出使用 base64 (main.rs:383)
**问题**: base64 编码增加 33% 的带宽开销，对于终端输出可能有性能影响

## 建议改进 📝

### 架构改进
1. **实现连接池**: 复用 SSH 连接，避免频繁创建/销毁
2. **添加限流**: 防止滥用和 DoS 攻击
3. **健康检查**: 添加 `/health` 端点
4. **指标收集**: 添加 Prometheus metrics

### 安全改进
1. **Session 超时**: WebSocket 连接应有最大生命周期
2. **并发限制**: 限制每个用户的并发连接数
3. **操作审计**: 记录执行的命令，不只是连接/断开
4. **RBAC**: 支持基于角色的访问控制

### 可维护性改进
1. **配置验证**: 启动时验证所有配置项
2. **优雅降级**: 某些功能失败时仍能继续服务
3. **结构化日志**: 使用 JSON 格式便于分析
4. **集成测试**: 添加端到端测试覆盖关键路径

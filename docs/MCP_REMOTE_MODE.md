# psh-mcp 远程模式支持（需求问题记录）

> **背景**：本文档记录 psh-mcp 当前仅支持 stdio 传输模式所带来的集成问题。
> 由使用方（CoPaw/QwenPaw agent）提出，供后续开发完善代码时参考。
> 目标分支：`feature/ssh-api`（psh-mcp MCP server 的代码均在 `cmd/psh-mcp` + `internal/mcp`）。

## 问题概述

`psh-mcp` 目前是**纯 stdio 模式**的 MCP server（`cmd/psh-mcp/main.go` 中
`mcp.NewServer(cfg)` 后 `srv.Run()`，启动日志固定打印
`psh-mcp server starting (stdio mode)`，且没有监听端口 / HTTP / SSE 传输的实现）。

这意味着 MCP 客户端（如 QwenPaw、Claude Desktop 等）**必须在本地拉起 psh-mcp 子进程**，
通过标准输入输出进行 JSON-RPC 通信。无法把 psh-mcp 作为**常驻远程服务**部署，
再让客户端通过 SSE / HTTP+JSON 方式远程连接。

## 实际部署中暴露的问题

使用方（CoPaw/QwenPaw agent 环境）原本的设想：

> 把 psh（含 psh-mcp）部署在远程跳板机/开发机（如 192.168.10.202），
> 客户端远程连接该 MCP server。

但受限于 stdio 模式，实际不得不：

1. 在客户端本地容器内放置 psh-mcp 二进制 + SSH 私钥 + `~/.ssh/config`。
2. 将 psh-mcp 注册为客户端本地的一个 stdio MCP client。

带来的直接风险 / 不便：

- **镜像更新即失联**：客户端运行容器一旦重建（镜像升级），本地放置的
  `psh-mcp` 二进制、SSH 私钥、SSH config、MCP card 配置全部丢失，
  MCP 通道随之断开，需要人工重新部署。
- **私钥分散**：SSH 私钥需复制到客户端环境，增加密钥泄露面。
- **不易多端共用**：每台客户端都要自带一份二进制和密钥，无法在服务端统一管理白名单、审计、密钥。
- **运维不透明**：psh-mcp 进程生命周期跟随客户端，无法用 docker/systemd 统一守护。

## 期望能力（需求）

参考 MCP 官方传输规范，增加**远程传输模式**，例如：

- `--transport sse` 或 `--transport http`：启动 HTTP/SSE 监听（如 `--listen :18080`），
  常驻在远程主机（可跑在 psh 现有容器/镜像里，与 WebSSH 同镜像）。
- 客户端通过 `transport: sse` + `url: http://<host>:18080/...` 远程连接。
- 保留现有 stdio 模式作为默认，不破坏现有用法。

加分项：

- 请求认证（token / API key，`PSH_API_KEY_ID` 已有类似字段可扩展）。
- TLS 支持，避免明文传输 SSH 指令。
- 与现有 `PSH_API_ALLOWED_HOSTS` 白名单、审计日志（`PSH_AUDIT_LOG`）保持兼容。

## 相关代码位置

| 文件 | 说明 |
|------|------|
| `cmd/psh-mcp/main.go` | 入口，读环境变量、NewServer、Run()，写死了 stdio |
| `internal/mcp/server.go` | MCP server 实现（JSON-RPC 工具注册：ssh_exec / ssh_session_create / ssh_session_exec / ssh_session_close） |
| `internal/mcp/` | 其他 MCP 相关（限流、会话等） |

## 测试环境参考（2026-08-18 已实测）

- 服务端（dev/跳板机）：`192.168.10.202`，Docker 29.2.1，Go 1.26。
- 已构建镜像 `psh:test`（同时含 `psh` 与 `psh-mcp`），容器 `psh-test`（WebSSH，端口 18443）、
  `psh-mcp-test`（MCP 测试容器）。
- 本地 stdio 模式验证通过：`ssh_exec` / `ssh_session_create` / `ssh_session_exec` / `ssh_session_close`
  4 个工具全链路（白名单 → SSH config 解析 → 密钥认证 → 命令执行）均 OK；
  `psh-mcp` 支持的关键 env：`PSH_API_ALLOWED_HOSTS`（白名单）、`PSH_API_SESSION_TIMEOUT` /
  `PSH_API_SESSION_MAX_LIFE` / `PSH_API_EXEC_TIMEOUT`、`PSH_MCP_RATE_LIMIT` / `PSH_MCP_MAX_SESSIONS`、
  `PSH_AUDIT_LOG` / `PSH_AUDIT_LEVEL`。

## 备注

- 若实现远程模式，建议在新分支或本分支继续开发，别把实验性改动直接合入 `main`（当前 `feature/ssh-api` 本身也尚未合入 main）。
- 需要与服务端常驻部署结合时，可在 Dockerfile 中同时启动 psh（WebSSH）与 psh-mcp（远程模式），或提供单独 entrypoint。

---

# 实现说明（2026-08-18，feature/ssh-api）

远程传输模式已实现，覆盖上文全部需求与加分项：

## 能力

- `--transport sse`（或 `PSH_MCP_TRANSPORT=sse`）：启动常驻 HTTP/SSE 监听（MCP 规范 2024-11-05 的 "HTTP with SSE" 传输），客户端用 `transport: sse` + `url: http://<host>:<port>/sse` 连接。
- `--listen`（或 `PSH_MCP_LISTEN`）：监听地址，默认 `:18080`。
- **stdio 模式保持默认**，现有用法不受影响。
- 端点：
  - `GET /sse`：建立 SSE 流，首个 `endpoint` 事件携带本连接的 `/messages?sessionId=...` 地址；
  - `POST /messages?sessionId=<id>`：投递 JSON-RPC 消息，响应经 SSE 流回传（202 Accepted）；
  - `GET /healthz`：存活探针（docker/systemd 守护用）。
- **请求认证**：`PSH_MCP_API_KEYS` 配置 Bearer token（逗号分隔，或指向密钥文件的路径，一行一个、支持 `#` 注释，与 Web 端 `PSH_API_KEYS` 语义一致）。远程模式 **fail-closed**：未配置任何密钥时拒绝启动；连接与其创建者的 token 绑定，其他 token 无法驱动该连接。token 同时作为限流与审计身份。
- **TLS**：`--tls-cert` / `--tls-key`（或 `PSH_TLS_CERT` / `PSH_TLS_KEY`）启用证书；`--auto-certs`（`PSH_AUTO_CERTS=true`）自动生成自签证书；均未配置时明文 HTTP 并打印告警。
- **兼容既有机制**：`PSH_API_ALLOWED_HOSTS` 白名单、`PSH_AUDIT_LOG` / `PSH_AUDIT_LEVEL` 审计、`PSH_MCP_RATE_LIMIT` / `PSH_MCP_RATE_WINDOW`（远程模式下按 token 维度限流）、`PSH_MCP_MAX_SESSIONS` 并发会话上限均继续生效。
- **资源保护**：`PSH_MCP_MAX_CONNECTIONS`（默认 100）限制并发 SSE 连接，超限返回 429；单连接待处理请求（含排队中）与响应缓冲均有上限，慢客户端会被主动断开；POST body 大小（1 MiB）与读取超时受限。
- **代理头信任**：endpoint URL 默认不信任 `X-Forwarded-Proto` / `X-Forwarded-Host`；仅在受信反向代理后部署时设置 `PSH_MCP_TRUST_PROXY_HEADERS=true`。
- SIGINT/SIGTERM 优雅退出；SSE 流每 15s 发送 keepalive 注释行，防止代理掐断长连接。

## 用法示例

服务端（跳板机常驻）：

```bash
PSH_API_ALLOWED_HOSTS=web-server,db-server \
PSH_MCP_API_KEYS=<your-secret-token> \
PSH_AUDIT_LOG=/var/log/psh/audit.jsonl \
psh-mcp --transport sse --listen :18080 --auto-certs
```

客户端（QwenPaw / Claude Desktop 等）：

```json
{
  "transport": "sse",
  "url": "https://192.168.10.202:18080/sse",
  "headers": { "Authorization": "Bearer <your-secret-token>" }
}
```

> 注：若客户端不支持自定义请求头，可在前置代理层注入 Authorization，或反馈后评估 query token 方案。

Docker 镜像已同时包含 `psh` 与 `psh-mcp` 两个二进制（EXPOSE 8443/18080），可分别以两个容器守护运行，例如：

```bash
docker run -d --name psh-mcp \
  -v ~/.ssh:/root/.ssh:ro \
  -p 18080:18080 \
  -e PSH_MCP_API_KEYS=<your-secret-token> \
  -e PSH_API_ALLOWED_HOSTS=web-server \
  epurs/psh:latest \
  /psh-mcp --transport sse --listen :18080
```

## 相关代码

| 文件 | 说明 |
|------|------|
| `internal/mcp/server.go` | 传输无关的 JSON-RPC 分发（stdio/SSE 共用），client 身份贯穿限流与审计 |
| `internal/mcp/sse.go` | SSE 传输实现（认证、连接注册、keepalive、优雅退出） |
| `internal/mcp/sse_test.go` | SSE 传输单元测试 |
| `cmd/psh-mcp/main.go` | `--transport` / `--listen` / TLS 参数与密钥加载 |
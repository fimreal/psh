# 内嵌 MCP 模式（单进程，与 WebSSH 共用鉴权）

> 本文档描述 `feature/mcp-integrated` 分支引入的**内嵌 MCP**：
> 一个 `/psh` 进程同时提供 WebSSH 界面和 MCP over SSE 服务，
> 两者共用同一套登录密码与审计日志。独立模式的 `cmd/psh-mcp`
>（stdio / 独立 SSE）继续可用，见 `docs/MCP_REMOTE_MODE.md`。

## 启用方式

```bash
PSH_MCP_ENABLED=true          # 挂载 /mcp/sse、/mcp/messages、/mcp/healthz
PSH_MCP_ALLOWED_HOSTS=dev,192.168.10.*,10.0.0.5   # 可选：SSH 目标白名单
PSH_MCP_EXEC_TIMEOUT=300s     # 可选：单命令超时
```

未设置 `PSH_MCP_ENABLED=true` 时行为与主线完全一致。

## 鉴权（与 webshell 相同的账号密码）

`/mcp/*` 不使用 JWT 会话，而是直接校验 **web 登录密码**
（即 `PSH_PASSWORD` 配置的那个）。三种写法等价：

```text
Authorization: Bearer <webshell密码>
Authorization: Basic base64(任意用户名:webshell密码)   # 兼容 HTTP Basic 客户端
# 或先 POST /api/auth/login 再使用 Bearer <psh_token>（JWT，可过期）
```

- 密码校验为常量时间比较；多密码配置时审计记录命中的凭据编号
  （`web-password-N`）。
- 无凭证 / 错误密码 → `401`。
- MCP 的限流、会话上限、目标白名单、审计全部沿用 `internal/mcp`
  已有机制。

## 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/mcp/sse` | MCP SSE 事件流（首条 event=endpoint 携带会话地址） |
| POST | `/mcp/messages?sessionId=...` | JSON-RPC 请求（initialize / tools/list / tools/call） |
| GET | `/mcp/healthz` | 存活探针 |
| GET | `/api/audit/recent?limit=N` | 最近 N 条审计事件（需 web 登录） |

## 工具

`ssh_exec`、`ssh_session_create`、`ssh_session_exec`、`ssh_session_close`。
SSH 连接逻辑不变：容器内 `/root/.ssh/config` 别名 + 私钥优先，
密码兜底；受 `PSH_API_ALLOWED_HOSTS` 同款白名单约束（内嵌模式变量名为
`PSH_MCP_ALLOWED_HOSTS`）。

## Web UI 可见性

Webshell 页面右下角新增「📋 活动」浮层，轮询 `/api/audit/recent`，
实时展示 MCP 工具调用与终端命令的审计流（时间 / 类型 / 凭据 / 主机 / 命令）。

## 客户端配置示例（QwenPaw / 任意 SSE-capable MCP client）

```json
{
  "transport": "sse",
  "url": "https://192.168.10.202:8443/mcp/sse",
  "headers": { "Authorization": "Bearer <webshell密码>" }
}
```

自签证书环境：客户端需关闭证书校验或导入 psh 生成的 CA/证书。

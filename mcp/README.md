# psh MCP Server

将 psh WebSSH 网关封装为 [MCP](https://modelcontextprotocol.io) 工具，让 AI agent（如 QwenPaw）可以安全地在 SSH 目标机上执行命令。

```
┌─────────────┐   stdio    ┌──────────────┐  HTTPS+WS  ┌─────────┐  ssh   ┌──────────┐
│  AI Agent   │◄──────────►│ mcp/server.py │◄──────────►│   psh   │───────►│ 目标主机  │
│  (QwenPaw)  │            │  (本目录)      │  自签 TLS  │ 容器     │ 密钥优先 │          │
└─────────────┘            └──────────────┘            └─────────┘        └──────────┘
```

## 生产部署步骤

### 1. 部署 psh 服务（目标网关机）

在部署机上：

```bash
mkdir -p /opt/psh/mcp && cd /opt/psh
# 放入 docker-compose.yml（本目录）后：
cat > .env <<'EOF'
PSH_PASSWORD=<openssl rand -base64 24 生成>
PSH_JWT_SECRET=<openssl rand -hex 32 生成>
EOF
docker compose up -d
docker compose logs -f psh   # 看到 "Starting HTTPS server" 即成功
```

要点：

- **SSH 配置复用**：compose 将宿主机 `/root/.ssh` 挂载进容器，psh 发起 SSH 连接时
  会使用 root 的 `~/.ssh/config`、私钥（`id_ed25519`/`id_rsa`）与 `known_hosts`，
  即"目标机怎么用 root 手工连，psh 就怎么连"。
- **known_hosts 写权限**：默认 TOFU 模式（`PSH_STRICT_HOST_KEY=false`）下 psh 首次连接
  会把新主机指纹写入 known_hosts，因此挂载不可加 `:ro`。若开启严格模式，请提前手工
  填好 known_hosts 并可将挂载改只读。
- **端口绑定**：默认只绑 `127.0.0.1:8443`。MCP server 与 psh 同机部署时最安全；
  若 Web 界面需局域网访问再自行放开并收敛防火墙。

### 2. 安装 MCP server（QwenPaw 所在机器）

```bash
pip install -r mcp/requirements.txt   # mcp, websockets, httpx
```

### 3. 配置环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `PSH_URL` | ✅ | 如 `https://127.0.0.1:8443` |
| `PSH_PASSWORD` | ✅ | psh Web 登录密码 |
| `PSH_CA_FILE` | | 置信 CA 后可开启 TLS 校验；不填且 `PSH_TLS_INSECURE=1` 则接受自签证书 |
| `PSH_TLS_INSECURE` | | 默认 `1` 接受自签；生产建议导入 CA 后设 `0` |
| `PSH_SSH_USER` | | target 未带 `user@` 时使用的默认用户（默认 root） |
| `PSH_SSH_PASSWORD` | | 密码认证兜底；**优先配置密钥认证**，此项留空 |
| `PSH_KNOWN_TARGETS` | | 预定义目标：`name=user@host:port,...`，供按名引用与白名单展示 |
| `PSH_MAX_OUTPUT` | | 输出截断阈值字节（默认 32000） |

### 4. 注册到 QwenPaw

```bash
curl -X POST http://<qwenpaw>:8080/api/agents/<agent_id>/mcp \
  -H "Content-Type: application/json" -d '{
  "client_key": "psh",
  "client": {
    "name": "psh",
    "description": "psh WebSSH gateway: run commands on SSH targets",
    "enabled": true,
    "transport": "stdio",
    "command": "/usr/bin/python3",
    "args": ["/opt/psh/mcp/server.py"],
    "env": {
      "PSH_URL": "https://127.0.0.1:8443",
      "PSH_PASSWORD": "<同 .env>",
      "PSH_SSH_USER": "root",
      "PSH_KNOWN_TARGETS": "dev=root@192.168.10.202"
    }
  }
}'
```

验证：`GET /api/agents/<agent_id>/mcp/tools/psh` 应返回 3 个工具定义。
平台响应会自动脱敏密钥字段。

## 工具说明

| 工具 | 只读 | 用途 |
|---|---|---|
| `psh_status` | ✅ | 登录态、TLS 校验状态、延迟 |
| `psh_targets` | ✅ | 列出 `PSH_KNOWN_TARGETS` 预定义目标 |
| `psh_exec` | ❌ | 在目标机执行单条命令，返回 stdout/stderr 与 exit code |

`psh_exec` 参数：`target`（`[user@]host[:port]` 或 KNOWN_TARGETS 里的名字）、
`command`、`timeout≤300`、可选 `ssh_password` 覆盖。

## 安全清单

- [x] psh 不暴露公网；默认仅绑回环，跨机访问走 VPN/防火墙白名单
- [x] 强随机 `PSH_PASSWORD` + 固定 `PSH_JWT_SECRET`
- [x] SSH 认证**优先密钥**（复用 root 的 ~/.ssh），密码仅为兜底
- [x] 平台侧工具调用默认 `ask` 审批；高危命令模式内置拦截（`rm -rf /`、mkfs、fork 炸弹）
- [x] 命令审计日志（`PSH_AUDIT_LEVEL=command`）落盘 `./data/audit`
- [x] 错误路径自动脱敏所有已配置密钥
- 建议：为多台不同凭据的主机扩展 per-target 配置，或全部改用密钥认证

## 故障排查

| 现象 | 原因与处理 |
|---|---|
| 登录 401 | `PSH_PASSWORD` 与 psh 启动配置不一致 |
| WS 握手 401 | psh 组级中间件只认 Cookie/Bearer 头（server 已处理），确认未改动鉴权头 |
| `ssh handshake failed ... no supported methods remain` | 用户名错误或目标机未配置对应密钥/密码 |
| `target asked for password but none configured` | 目标机没有可用公钥；配密钥或设 `PSH_SSH_PASSWORD` |
| `completed: false` | 命令超时或长时间无输出；加大 `timeout` 或检查目标机负载 |
| exit_code 为 null 但有输出 | 命令未正常收尾（如交互式程序）；避免执行需要 TTY 交互的命令 |

## 协议备忘（二次开发）

- REST 登录：`POST /api/auth/login {"password"}` → `Set-Cookie psh_token`（JWT）
- WS 终端：`GET /ws/terminal`，组级 AuthMiddleware **只认 Cookie/Bearer 头**
- mini-shell 仅支持 `ssh/help/clear/exit`；收到 `\n` 异步执行
- 远端为真实 PTY，会回显输入 → 结束标记按出现次数 ≥2 判定，exit code 解析前先剥离 ANSI 序列

# psh - WebSSH Proxy

> 浏览器 SSH 跳板机 - 在受限网络中通过 Web 连接 SSH 服务器

## 功能特性

- **多标签终端** - 支持同时打开多个 SSH 会话
- **SSH 配置集成** - 挂载 `~/.ssh/config` 和密钥，支持标准 SSH 配置
- **安全访问** - 默认自签名 HTTPS，支持配置正式证书
- **Web 登录** - JWT 鉴权，单用户场景
- **审计日志** - JSONL 格式的连接和命令日志

## 快速开始

### Docker 运行

```bash
docker run -d \
  --name psh \
  --restart always \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-secure-password \
  ghcr.io/epurs/psh:latest
```

然后访问 https://localhost:8443

### 使用 Docker Compose

```yaml
version: '3.8'
services:
  psh:
    image: ghcr.io/epurs/psh:latest
    ports:
      - "8443:8443"
    volumes:
      - ~/.ssh:/root/.ssh:ro
    environment:
      - PSH_PASSWORD=your-secure-password
    restart: always
```

## 配置

### 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `PSH_PASSWORD` | **是** | - | Web 登录密码 |
| `PSH_HOST` | 否 | `0.0.0.0` | 监听地址 |
| `PSH_PORT` | 否 | `8443` | HTTPS 端口 |
| `PSH_JWT_SECRET` | 否 | 自动生成 | JWT 签名密钥 |
| `PSH_JWT_EXPIRE` | 否 | `86400` | Token 过期时间（秒） |
| `PSH_SSH_CONFIG` | 否 | `/root/.ssh/config` | SSH 配置路径 |
| `PSH_AUDIT_LOG` | 否 | `/var/log/psh/audit.jsonl` | 审计日志路径 |
| `PSH_TLS_CERT` | 否 | - | TLS 证书路径 |
| `PSH_TLS_KEY` | 否 | - | TLS 私钥路径 |
| `PSH_AUTO_CERTS` | 否 | `true` | 自动生成自签名证书 |

### SSH 配置

psh 会读取挂载的 `~/.ssh/config` 文件，自动识别可连接的主机：

```ssh
# ~/.ssh/config
Host my-server
    HostName 192.168.1.100
    User admin
    Port 22
    IdentityFile ~/.ssh/id_ed25519

Host another-server
    HostName example.com
    User root
```

### TLS 证书

默认情况下，psh 会自动生成自签名证书。对于生产环境，建议使用正式证书：

```bash
docker run -d \
  --name psh \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -v /path/to/cert.pem:/etc/ssl/cert.pem:ro \
  -v /path/to/key.pem:/etc/ssl/key.pem:ro \
  -e PSH_PASSWORD=your-password \
  -e PSH_TLS_CERT=/etc/ssl/cert.pem \
  -e PSH_TLS_KEY=/etc/ssl/key.pem \
  psh:latest
```

## 从源码构建

```bash
# 克隆仓库
git clone https://git.epurs.com/psh
cd psh

# 构建
cargo build --release

# 运行
PSH_PASSWORD=your-password ./target/release/psh
```

## 审计日志

审计日志以 JSONL 格式记录，每行一个 JSON 对象：

```json
{"timestamp":"2024-01-15T10:30:00Z","type":"connection","session_id":"abc123","host":"my-server","user":"admin"}
{"timestamp":"2024-01-15T10:35:00Z","type":"disconnection","session_id":"abc123","host":"my-server"}
```

## API 参考

### REST API

#### 登录

```http
POST /api/auth/login
Content-Type: application/json

{
  "password": "your-password"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 86400
}
```

#### 获取主机列表

```http
GET /api/hosts
Authorization: Bearer <token>

Response:
[
  {
    "name": "my-server",
    "hostname": "192.168.1.100",
    "user": "admin",
    "port": 22
  }
]
```

### WebSocket 协议

连接：`wss://host/ws/terminal?token=<jwt>`

消息格式（JSON）：

```typescript
// Client -> Server
{
  "type": "connect",
  "host": "my-server",
  "user": "admin",  // optional
  "port": 22       // optional
}

{
  "type": "input",
  "data": "base64-encoded-data"
}

{
  "type": "resize",
  "cols": 120,
  "rows": 40
}

// Server -> Client
{
  "type": "connected",
  "session_id": "uuid",
  "host": "my-server",
  "user": "admin"
}

{
  "type": "output",
  "data": "base64-encoded-data"
}

{
  "type": "error",
  "message": "Error description"
}
```

## 技术栈

- **后端**: Rust (axum, russh, tokio-tungstenite, jsonwebtoken)
- **前端**: TypeScript (xterm.js)
- **容器**: Alpine Linux

## 许可证

MIT

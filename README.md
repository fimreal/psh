# psh - WebSSH Proxy

> 浏览器 SSH 跳板机 - 在受限网络中通过 Web 连接 SSH 服务器

## 功能特性

- **多标签终端** - 支持同时打开多个 SSH 会话
- **SSH 配置集成** - 挂载 `~/.ssh/config` 和密钥，支持标准 SSH 配置
- **安全访问** - 默认自签名 HTTPS，支持配置正式证书
- **Web 登录** - JWT 鉴权，单用户场景
- **审计日志** - JSONL 格式的连接和命令日志
- **多架构支持** - 原生支持 Linux 和 macOS 的 AMD64/ARM64 架构

## 安装

### 方式一：使用预编译二进制文件（推荐）

从 [Releases](https://github.com/your-org/psh/releases) 页面下载适合你系统的版本：

**Linux (AMD64/x86_64)**
```bash
# 下载
wget https://github.com/your-org/psh/releases/latest/download/psh-linux-amd64.tar.gz
# 解压
tar -xzf psh-linux-amd64.tar.gz
# 验证
sha256sum -c psh-linux-amd64.sha256
# 运行
sudo mv psh /usr/local/bin/
PSH_PASSWORD=your-password psh
```

**Linux (ARM64/aarch64)**
```bash
wget https://github.com/your-org/psh/releases/latest/download/psh-linux-arm64.tar.gz
tar -xzf psh-linux-arm64.tar.gz
sha256sum -c psh-linux-arm64.sha256
sudo mv psh /usr/local/bin/
PSH_PASSWORD=your-password psh
```

**macOS (Apple Silicon)**
```bash
wget https://github.com/your-org/psh/releases/latest/download/psh-darwin-arm64.tar.gz
tar -xzf psh-darwin-arm64.tar.gz
shasum -a 256 -c psh-darwin-arm64.sha256
sudo mv psh /usr/local/bin/
PSH_PASSWORD=your-password psh
```

**macOS (Intel)**
```bash
wget https://github.com/your-org/psh/releases/latest/download/psh-darwin-amd64.tar.gz
tar -xzf psh-darwin-amd64.tar.gz
shasum -a 256 -c psh-darwin-amd64.sha256
sudo mv psh /usr/local/bin/
PSH_PASSWORD=your-password psh
```

### 方式二：使用 Docker（支持多架构）

Docker 镜像支持以下架构：
- `linux/amd64` (x86_64)
- `linux/arm64` (aarch64)

Docker 会自动选择适合你系统的架构：

```bash
# 将 yourusername 替换为你的 Docker Hub 用户名
docker run -d \
  --name psh \
  --restart always \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-secure-password \
  yourusername/psh:latest
```

指定特定架构：
```bash
# AMD64
docker run -d \
  --platform linux/amd64 \
  --name psh \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-password \
  yourusername/psh:latest

# ARM64
docker run -d \
  --platform linux/arm64 \
  --name psh \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-password \
  yourusername/psh:latest
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

### 方式三：从源码构建

**依赖要求**
- Rust 1.70+ (推荐 1.88+)
- OpenSSL 开发库

**Linux 构建**
```bash
# 安装依赖 (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

# 安装依赖 (CentOS/RHEL)
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel

# 克隆仓库
git clone https://git.epurs.com/psh
cd psh

# 构建
cargo build --release

# 运行
PSH_PASSWORD=your-password ./target/release/psh
```

**macOS 构建**
```bash
# 安装依赖
brew install openssl

# 克隆仓库
git clone https://git.epurs.com/psh
cd psh

# 构建
cargo build --release

# 运行
PSH_PASSWORD=your-password ./target/release/psh
```

**交叉编译 ARM64**
```bash
# 安装交叉编译工具链
sudo apt-get install -y gcc-aarch64-linux-gnu

# 设置链接器
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

# 构建 ARM64 二进制
cargo build --release --target aarch64-unknown-linux-gnu
```

**构建静态二进制（Alpine Linux）**
```bash
# 使用静态链接
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-musl
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

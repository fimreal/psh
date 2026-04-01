# psh - WebSSH Proxy

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-org/psh/build.yml?branch=main)](https://github.com/your-org/psh/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/yourusername/psh.svg)](https://hub.docker.com/r/yourusername/psh)
[![License](https://img.shields.io/github/license/your-org/psh.svg)](LICENSE)
[![Release](https://img.shields.io/github/release/your-org/psh.svg)](https://github.com/your-org/psh/releases)

> 🚀 浏览器 SSH 跳板机 - 在受限网络中通过 Web 安全连接 SSH 服务器

**简体中文** | [English](#english)

---

## ✨ 功能特性

- 🔐 **安全访问** - JWT 认证 + TLS/HTTPS 加密，自动生成自签名证书
- 📑 **多标签终端** - 支持同时打开多个 SSH 会话，快捷键切换
- ⚙️ **SSH 配置集成** - 自动读取 `~/.ssh/config`，支持标准 SSH 配置和密钥
- 📊 **审计日志** - JSONL 格式记录所有会话，满足合规要求
- 🐳 **多架构支持** - 原生支持 Linux/macOS 的 AMD64/ARM64，Docker 多架构镜像
- 🎨 **现代界面** - 基于 xterm.js 的全功能终端，支持主题定制
- ⚡ **高性能** - Rust 异步运行时，极低资源占用

---

## 📦 快速开始

### 使用 Docker（最简单）

```bash
docker run -d \
  --name psh \
  --restart always \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-secure-password \
  yourusername/psh:latest
```

访问 https://localhost:8443 并使用设置的密码登录。

### 使用预编译二进制

从 [Releases](https://github.com/your-org/psh/releases) 下载对应平台的二进制文件：

```bash
# Linux/macOS 示例
wget https://github.com/your-org/psh/releases/latest/download/psh-linux-amd64.tar.gz
tar -xzf psh-linux-amd64.tar.gz
sudo mv psh /usr/local/bin/
PSH_PASSWORD=your-password psh
```

### 使用 Docker Compose

创建 `docker-compose.yml`：

```yaml
version: '3.8'
services:
  psh:
    image: yourusername/psh:latest
    container_name: psh
    restart: unless-stopped
    ports:
      - "8443:8443"
    volumes:
      - ~/.ssh:/root/.ssh:ro
      - psh-logs:/var/log/psh
    environment:
      - PSH_PASSWORD=${PSH_PASSWORD}
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8443/"]
      interval: 30s
      timeout: 3s
      retries: 3

volumes:
  psh-logs:
```

```bash
echo "PSH_PASSWORD=your-secure-password" > .env
docker-compose up -d
```

---

## 📖 详细文档

### 环境变量配置

| 变量 | 必填 | 默认值 | 说明 |
|------|:----:|--------|------|
| `PSH_PASSWORD` | ✅ | - | Web 登录密码（**必填**） |
| `PSH_HOST` | | `0.0.0.0` | 监听地址 |
| `PSH_PORT` | | `8443` | HTTPS 端口 |
| `PSH_JWT_SECRET` | | 自动生成 | JWT 签名密钥（生产环境建议设置） |
| `PSH_JWT_EXPIRE` | | `86400` | Token 过期时间（秒） |
| `PSH_SSH_CONFIG` | | `/root/.ssh/config` | SSH 配置文件路径 |
| `PSH_AUDIT_LOG` | | `/var/log/psh/audit.jsonl` | 审计日志路径 |
| `PSH_TLS_CERT` | | - | TLS 证书路径 |
| `PSH_TLS_KEY` | | - | TLS 私钥路径 |
| `PSH_AUTO_CERTS` | | `true` | 自动生成自签名证书 |

### SSH 配置示例

psh 自动读取挂载的 `~/.ssh/config`：

```ssh
# ~/.ssh/config
Host web-server
    HostName 192.168.1.100
    User admin
    Port 22
    IdentityFile ~/.ssh/id_ed25519

Host db-server
    HostName db.example.com
    User postgres
    Port 5432
    IdentityFile ~/.ssh/id_rsa
```

支持的 SSH 配置项：
- `HostName` - 主机地址
- `User` - 登录用户
- `Port` - SSH 端口
- `IdentityFile` - 私钥路径

### TLS 证书配置

**自动生成（开发/测试）**

默认启用，自动生成自签名证书。浏览器会提示不安全，点击继续访问即可。

**自定义证书（生产环境）**

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
  -e PSH_AUTO_CERTS=false \
  yourusername/psh:latest
```

### 审计日志

日志格式：JSONL（每行一个 JSON 对象）

```json
{"timestamp":"2024-01-15T10:30:00Z","type":"connection","session_id":"abc123","host":"web-server","user":"admin"}
{"timestamp":"2024-01-15T10:35:00Z","type":"disconnection","session_id":"abc123","host":"web-server"}
{"timestamp":"2024-01-15T10:40:00Z","type":"error","session_id":"def456","host":"db-server","error":"Authentication failed"}
```

查看日志：
```bash
# 实时查看
tail -f /var/log/psh/audit.jsonl | jq .

# 筛选连接记录
cat /var/log/psh/audit.jsonl | jq 'select(.type == "connection")'
```

---

## 🔧 高级配置

### 从源码构建

**依赖要求**
- Rust 1.70+（推荐 1.88+）
- OpenSSL 开发库

**构建步骤**

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆仓库
git clone https://git.epurs.com/gitops/psh.git
cd psh

# 安装依赖（Ubuntu/Debian）
sudo apt-get install -y build-essential pkg-config libssl-dev

# 构建
cargo build --release

# 运行
PSH_PASSWORD=your-password ./target/release/psh
```

**交叉编译**

```bash
# ARM64 Linux
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install -y gcc-aarch64-linux-gnu
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
cargo build --release --target aarch64-unknown-linux-gnu

# 静态链接（Alpine Linux）
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-musl
```

---

## 🌐 API 参考

### REST API

#### 登录获取 Token

```http
POST /api/auth/login
Content-Type: application/json

{
  "password": "your-password"
}
```

响应：
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 86400
}
```

#### 获取主机列表

```http
GET /api/hosts
Authorization: Bearer <token>
```

响应：
```json
[
  {
    "name": "web-server",
    "hostname": "192.168.1.100",
    "user": "admin",
    "port": 22
  }
]
```

### WebSocket 协议

连接端点：`wss://your-host/ws/terminal?token=<jwt>`

**客户端 → 服务器**

```typescript
// 连接到 SSH 主机
{
  "type": "connect",
  "host": "web-server",
  "user": "admin",  // 可选
  "port": 22       // 可选
}

// 终端输入（base64 编码）
{
  "type": "input",
  "data": "bHMgLWwK"
}

// 调整终端大小
{
  "type": "resize",
  "cols": 120,
  "rows": 40
}
```

**服务器 → 客户端**

```typescript
// 连接成功
{
  "type": "connected",
  "session_id": "uuid",
  "host": "web-server",
  "user": "admin"
}

// 终端输出（base64 编码）
{
  "type": "output",
  "data": "dG90YWwgMTIzNDUK"
}

// 错误消息
{
  "type": "error",
  "message": "Connection refused"
}
```

---

## 🐛 故障排查

### 无法连接到 SSH 主机

1. **检查 SSH 配置**
   ```bash
   # 测试 SSH 连接
   ssh -F ~/.ssh/config web-server

   # 检查密钥权限
   chmod 600 ~/.ssh/id_ed25519
   ```

2. **检查 Docker 挂载**
   ```bash
   # 确保挂载了 SSH 配置和密钥
   docker exec psh ls -la /root/.ssh
   ```

3. **查看日志**
   ```bash
   docker logs psh | grep -i error
   ```

### 浏览器提示证书不安全

这是自签名证书的正常行为：
- **开发环境**：点击"高级" → "继续访问"
- **生产环境**：配置正式 TLS 证书

### JWT Token 过期

Token 默认 24 小时过期，重新登录即可。可在 `PSH_JWT_EXPIRE` 中调整过期时间。

---

## 🛡️ 安全最佳实践

1. **使用强密码**
   ```bash
   # 生成随机密码
   openssl rand -base64 32
   ```

2. **配置防火墙**
   ```bash
   # 仅允许特定 IP 访问
   ufw allow from 192.168.1.0/24 to any port 8443
   ```

3. **使用正式 TLS 证书**
   - Let's Encrypt（免费）
   - 商业 SSL 证书

4. **定期检查审计日志**
   ```bash
   # 监控失败的连接尝试
   cat /var/log/psh/audit.jsonl | jq 'select(.type == "error")'
   ```

5. **限制 SSH 密钥权限**
   ```bash
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/id_ed25519
   chmod 644 ~/.ssh/id_ed25519.pub
   ```

---

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/amazing-feature`
3. 提交更改：`git commit -m 'Add amazing feature'`
4. 推送分支：`git push origin feature/amazing-feature`
5. 提交 Pull Request

---

## 📄 许可证

本项目采用 [MIT 许可证](LICENSE)。

---

## 🙏 致谢

- [russh](https://github.com/warp-tech/russh) - 纯 Rust SSH 实现
- [axum](https://github.com/tokio-rs/axum) - 高性能 Web 框架
- [xterm.js](https://xtermjs.org/) - 强大的终端模拟器

---

## 📮 联系方式

- 问题反馈：[GitHub Issues](https://github.com/your-org/psh/issues)
- 功能建议：[GitHub Discussions](https://github.com/your-org/psh/discussions)

---

<p align="center">
  Made with ❤️ by the psh team
</p>

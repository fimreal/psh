# psh - WebSSH Proxy

[![Build Status](https://git.epurs.com/gitops/psh/actions/workflows/build.yml/badge.svg?branch=main)](https://git.epurs.com/gitops/psh/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/docker/v/epurs/psh/latest?label=docker)](https://hub.docker.com/r/epurs/psh)

> 🚀 浏览器 SSH 跳板机 - 在受限网络中通过 Web 安全连接 SSH 服务器

---

## ✨ 功能特性

- 🔐 **安全访问** - JWT 认证 + TLS/HTTPS 加密，自动生成自签名证书
- 📑 **多标签终端** - 支持同时打开多个 SSH 会话，快捷键切换
- ⚙️ **SSH 配置集成** - 自动读取 `~/.ssh/config`，支持标准 SSH 配置和密钥
- 📊 **审计日志** - JSONL 格式记录所有会话，满足合规要求
- 🐳 **多架构支持** - 原生支持 Linux/macOS 的 AMD64/ARM64，Docker 多架构镜像
- 🎨 **现代界面** - 基于 xterm.js 的全功能终端，支持主题定制
- ⚡ **高性能** - Go 并发模型，极低资源占用

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
  epurs/psh:latest
```

访问 https://localhost:8443 并使用设置的密码登录。

### 使用预编译二进制

从 [Releases](https://git.epurs.com/gitops/psh/releases) 下载对应平台的二进制文件：

```bash
# Linux/macOS 示例
wget https://git.epurs.com/gitops/psh/releases/latest/download/psh-linux-amd64
chmod +x psh-linux-amd64
sudo mv psh-linux-amd64 /usr/local/bin/psh
PSH_PASSWORD=your-password psh
```

### 使用 Docker Compose

创建 `docker-compose.yml`：

```yaml
services:
  psh:
    image: epurs/psh:latest
    container_name: psh
    restart: unless-stopped
    ports:
      - "8443:8443"
    volumes:
      - ~/.ssh:/root/.ssh:ro
    environment:
      - PSH_PASSWORD=${PSH_PASSWORD}
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
| `PSH_PORT` | | `8443` | HTTPS 端口（dev 模式默认 8080） |
| `PSH_JWT_SECRET` | | 自动生成 | JWT 签名密钥（生产环境建议设置） |
| `PSH_JWT_EXPIRE` | | `86400` | Token 过期时间（秒） |
| `PSH_SSH_CONFIG` | | `/root/.ssh/config` | SSH 配置文件路径 |
| `PSH_AUDIT_LOG` | | `-` | 审计日志路径（`-` 为 stdout，空则禁用） |
| `PSH_AUDIT_LEVEL` | | `command` | 审计级别：off, connection, command, command-full |
| `PSH_TLS_CERT` | | - | TLS 证书路径 |
| `PSH_TLS_KEY` | | - | TLS 私钥路径 |
| `PSH_AUTO_CERTS` | | `true` | 自动生成自签名证书 |
| `PSH_SSH_BLACKLIST` | | `127.0.0.0/8` | SSH 黑名单（CIDR 格式，逗号分隔） |
| `PSH_ALLOWED_ORIGINS` | | `*` | CORS 允许的域名（逗号分隔，默认允许所有） |
| `PSH_MAX_WS_CONNS` | | `10` | 每分钟每 IP 最大 WebSocket 连接数 |

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
  -v /path/to/cert.pem:/etc/psh/cert.pem:ro \
  -v /path/to/key.pem:/etc/psh/key.pem:ro \
  -e PSH_PASSWORD=your-password \
  -e PSH_TLS_CERT=/etc/psh/cert.pem \
  -e PSH_TLS_KEY=/etc/psh/key.pem \
  -e PSH_AUTO_CERTS=false \
  epurs/psh:latest
```

### SSH 黑名单

出于安全考虑，默认禁止通过 psh SSH 连接到本地回环地址（`127.0.0.0/8`）。这可以防止用户通过 Web 终端访问宿主机。

**自定义黑名单**

```bash
# 禁止多个网段
docker run -d \
  --name psh \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-password \
  -e PSH_SSH_BLACKLIST="127.0.0.0/8,10.0.0.0/8,192.168.0.0/16" \
  epurs/psh:latest

# 禁用黑名单（允许 SSH 到任何地址，不推荐）
docker run -d \
  --name psh \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-password \
  -e PSH_SSH_BLACKLIST="" \
  epurs/psh:latest
```

或使用命令行参数：

```bash
# 自定义黑名单
psh --ssh-blacklist "127.0.0.0/8,10.0.0.0/8"

# 禁用黑名单
psh --ssh-blacklist ""
```

### CORS 配置

默认允许所有域名跨域访问。如果前端部署在独立域名，可以配置允许的域名：

```bash
# 允许特定域名
docker run -d \
  --name psh \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-password \
  -e PSH_ALLOWED_ORIGINS="https://shell.example.com,https://terminal.example.com" \
  epurs/psh:latest
```

或使用命令行参数：

```bash
psh --allowed-origins "https://shell.example.com,https://terminal.example.com"
```

### 审计日志

默认输出到 stdout（适合容器环境），可通过环境变量配置：

```bash
# 输出到 stdout（默认）
PSH_AUDIT_LOG=- psh

# 输出到文件
PSH_AUDIT_LOG=/var/log/psh/audit.jsonl psh

# 禁用审计日志
PSH_AUDIT_LOG= psh
```

**审计级别** (`PSH_AUDIT_LEVEL`)：

| 级别 | 说明 |
|------|------|
| `off` | 禁用审计 |
| `connection` | 仅记录连接/断开 |
| `command` | 记录命令名（不含参数，**默认**） |
| `command-full` | 记录完整命令（可能含敏感信息） |

日志格式：JSONL（每行一个 JSON 对象）

```json
{"timestamp":"2024-01-15T10:30:00Z","type":"connection","session_id":"abc123","host":"web-server","user":"admin"}
{"timestamp":"2024-01-15T10:30:05Z","type":"command","session_id":"abc123","host":"web-server","command":"ls -la"}
{"timestamp":"2024-01-15T10:30:10Z","type":"command","session_id":"abc123","host":"web-server","command":"cat /etc/passwd"}
{"timestamp":"2024-01-15T10:35:00Z","type":"disconnection","session_id":"abc123","host":"web-server"}
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
- Go 1.22+

**构建步骤**

```bash
# 克隆仓库
git clone https://git.epurs.com/gitops/psh.git
cd psh

# 构建
go build -o psh ./cmd/psh

# 运行
PSH_PASSWORD=your-password ./psh
```

**交叉编译**

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o psh-linux-amd64 ./cmd/psh

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o psh-linux-arm64 ./cmd/psh

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -o psh-darwin-amd64 ./cmd/psh

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o psh-darwin-arm64 ./cmd/psh
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
  "expires_in": 86400
}
```

Token 会通过 `Set-Cookie` 返回（HttpOnly Cookie）。

### WebSocket 协议

连接端点：`wss://your-host/ws/terminal`

认证通过 Cookie 中的 `psh_token` 完成。

**客户端 → 服务器**

```typescript
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

- [xterm.js](https://xtermjs.org/) - 强大的终端模拟器
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - SSH 协议实现

---

## 📮 联系方式

- 问题反馈：https://git.epurs.com/gitops/psh/issues

---

<p align="center">
  Made with ❤️
</p>

# psh - WebSSH Proxy

> 浏览器 SSH 跳板机 - 在受限网络中通过 Web 连接 SSH 服务器

## 项目信息

- **名称**: psh (proxy shell)
- **仓库**: https://git.epurs.com/psh
- **技术栈**: Rust + TypeScript
- **部署**: Alpine 容器

## 核心需求

1. **多标签终端** - 支持同时打开多个 SSH 会话
2. **SSH 配置集成** - 挂载 `~/.ssh/config` 和密钥，支持标准 SSH 配置
3. **安全访问** - 默认自签名 HTTPS，支持配置正式证书
4. **Web 登录** - JWT 鉴权，单用户场景

## 技术架构

### 后端 (Rust)

| 组件 | 依赖 | 用途 |
|------|------|------|
| Web 框架 | axum | HTTP/HTTPS 服务 |
| WebSocket | tokio-tungstenite | 终端双向通信 |
| SSH 客户端 | russh | SSH 协议实现 |
| 认证 | jsonwebtoken | JWT 鉴权 |

### 前端 (TypeScript)

| 组件 | 依赖 | 用途 |
|------|------|------|
| 终端渲染 | xterm.js | VT100 终端模拟 |
| WebSocket | 原生 WebSocket | 实时通信 |
| UI | 原生 DOM | 轻量无框架 |

## 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                        Browser                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Tab 1     │  │   Tab 2     │  │   Tab N     │         │
│  │  (xterm.js) │  │  (xterm.js) │  │  (xterm.js) │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                │
│         └────────────────┴────────────────┘                │
│                          │                                 │
│                    WebSocket (WSS)                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                    psh Container                         │
│  ┌───────────────────────┼───────────────────────┐          │
│  │   axum HTTPS server   │   JWT middleware      │          │
│  └───────────┬───────────┴───────────┬───────────┘          │
│              │                       │                      │
│  ┌───────────▼───────────┐  ┌───────▼────────┐               │
│  │   WebSocket handler   │  │   SSH manager  │               │
│  │   (per connection)    │  │   (russh)      │               │
│  └───────────┬───────────┘  └───────┬────────┘               │
│              │                       │                      │
│              └───────────┬───────────┘                      │
│                          │                                  │
│  ┌───────────────────────▼───────────────────────┐          │
│  │         ~/.ssh/config & keys (mounted)        │          │
│  └───────────────────────────────────────────────┘          │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## API 设计

### REST API

```http
# 登录获取 JWT
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

### WebSocket Protocol

连接：`wss://host/ws/terminal?token=<jwt>`

消息格式（JSON）：

```typescript
// Client -> Server
interface InputMessage {
  type: 'input';
  data: string;  // 用户输入的字节
}

interface ResizeMessage {
  type: 'resize';
  cols: number;
  rows: number;
}

// Server -> Client
interface OutputMessage {
  type: 'output';
  data: string;  // base64 编码的终端输出
}

interface ErrorMessage {
  type: 'error';
  message: string;
}
```

## 目录结构

```
psh/
├── Cargo.toml           # Rust workspace
├── DESIGN.md            # 本文档
├── Dockerfile           # Alpine 容器
├── README.md            # 项目说明
├── backend/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs      # 入口
│       ├── config.rs    # 配置
│       ├── auth.rs      # JWT 鉴权
│       ├── ws.rs        # WebSocket 处理
│       └── ssh.rs       # SSH 管理
└── frontend/
    ├── index.html
    ├── src/
    │   ├── main.ts      # 入口
    │   ├── terminal.ts  # xterm 封装
    │   └── ws.ts        # WebSocket 客户端
    └── package.json
```

## 配置

环境变量：

```bash
# 必填
PSH_PASSWORD=your-secure-password  # Web 登录密码

# 可选（有默认值）
PSH_HOST=0.0.0.0                   # 监听地址
PSH_PORT=8443                      # HTTPS 端口
PSH_JWT_SECRET=auto-generated      # JWT 签名密钥
PSH_JWT_EXPIRE=86400               # Token 过期时间（秒）
PSH_SSH_CONFIG=/root/.ssh/config   # SSH 配置路径
```

## 部署

### Docker 运行

```bash
docker run -d \
  --name psh \
  --restart always \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=your-password \
  psh:latest
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: psh
spec:
  replicas: 1
  selector:
    matchLabels:
      app: psh
  template:
    metadata:
      labels:
        app: psh
    spec:
      containers:
      - name: psh
        image: psh:latest
        ports:
        - containerPort: 8443
        env:
        - name: PSH_PASSWORD
          valueFrom:
            secretKeyRef:
              name: psh-secret
              key: password
        volumeMounts:
        - name: ssh-config
          mountPath: /root/.ssh
          readOnly: true
      volumes:
      - name: ssh-config
        secret:
          secretName: psh-ssh-config
---
apiVersion: v1
kind: Service
metadata:
  name: psh
spec:
  selector:
    app: psh
  ports:
  - port: 8443
    targetPort: 8443
```

## 里程碑

- [ ] M1: 基础架构（HTTPS + WebSocket 骨架）
- [ ] M2: SSH 连接（russh 集成）
- [ ] M3: 终端功能（xterm.js + 多标签）
- [ ] M4: 认证完善（JWT + 配置化）
- [ ] M5: 容器化（Docker + Alpine）
- [ ] M6: 文档完善（README + 部署指南）

## 相关链接

- [russh](https://github.com/warp-tech/russh) - Rust SSH 库
- [xterm.js](https://xtermjs.org/) - 终端模拟器
- [axum](https://github.com/tokio-rs/axum) - Rust Web 框架

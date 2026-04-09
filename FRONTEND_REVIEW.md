# 前端代码深度审查报告

## 严重问题 🔴

### 1. Token 存储在 localStorage (app.js:10, 108)
**位置**: `PshApp` 构造函数和 `handleLogin`
**问题**:
- JWT token 存储在 localStorage，容易被 XSS 攻击窃取
- 如果页面被注入恶意脚本，token 会被盗取

```javascript
this.token = localStorage.getItem('psh_token');
localStorage.setItem('psh_token', this.token);
```

**影响**: 安全漏洞，token 窃取
**修复**: 
- 使用 HttpOnly cookie 存储 token
- 或使用 sessionStorage（至少不会持久化）

### 2. XSS 漏洞 - 未转义用户输入 (app.js:198-199, 293)
**位置**: `createTerminalSession`
**问题**:
- `host` 参数直接插入 HTML，没有转义
- 如果 host 来自不可信源，可能导致 XSS

```javascript
tab.innerHTML = `
    <span class="tab-title">${host}</span>  // 未转义！
    <span class="tab-close">×</span>
`;
```

**影响**: XSS 攻击，恶意代码执行
**修复**: 使用 textContent 或转义 HTML

### 3. WebSocket URL 包含未编码参数 (app.js:259)
**位置**: `createTerminalSession`
**问题**:
- user 和 port 参数直接拼接到 URL
- 特殊字符可能破坏 URL 格式

```javascript
const wsUrl = `${wsProtocol}//${window.location.host}/ws/terminal?token=${encodeURIComponent(this.token)}`;
// 如果有 user 和 port 需要添加到 URL，但没有编码
```

**影响**: URL 注入
**修复**: 所有 URL 参数都需要 encodeURIComponent

### 4. base64 编码在错误的层 (app.js:283, 326)
**位置**: WebSocket 消息处理
**问题**:
- 终端输出用 base64 编码传输，增加带宽
- 输入也用 base64 编码，效率低
- 在前端解码/编码增加 CPU 开销

```javascript
const data = atob(msg.data);  // 解码 base64
ws.send(JSON.stringify({ type: 'input', data: btoa(data) }));  // 编码 base64
```

**影响**: 性能问题，带宽浪费
**修复**: 使用二进制 WebSocket 消息（ArrayBuffer）

### 5. 没有重连机制 (app.js:306-314)
**位置**: WebSocket onclose 处理
**问题**:
- WebSocket 断开后不会自动重连
- 用户需要手动重新连接，体验差
- 临时网络波动会导致会话丢失

**影响**: 用户体验差，连接不稳定
**修复**: 实现自动重连机制

## 高优先级问题 🟠

### 6. 错误处理不完善 (app.js:117-121, 139)
**位置**: `handleLogin` 和 `loadHosts`
**问题**:
- catch 块只打印错误到控制台，用户看不到
- `loadHosts` 失败后没有任何提示
- 网络错误没有重试机制

```javascript
} catch (e) {
    console.error('Failed to load hosts:', e);  // 用户看不到！
}
```

**影响**: 用户无法知道发生了什么错误
**修复**: 显示用户友好的错误消息

### 7. 没有输入验证 (app.js:160-184)
**位置**: `handleConnect`
**问题**:
- 手动输入的 host 格式没有严格验证
- port 可能被解析为 NaN
- user 可能包含特殊字符

```javascript
port = parseInt(hostParts[1]);  // 可能是 NaN
```

**影响**: 连接失败或安全问题
**修复**: 添加输入验证和清理

### 8. WebSocket 消息解析不安全 (app.js:276-304)
**位置**: `ws.onmessage`
**问题**:
- JSON.parse 失败时会回退到纯文本（第 301 行）
- 但纯文本可能包含恶意内容
- 没有验证消息格式

```javascript
} catch (e) {
    term.write(event.data);  // 直接写入终端！
}
```

**影响**: 终端可能被注入控制序列
**修复**: 严格验证消息格式

### 9. ResizeObserver 可能导致性能问题 (app.js:348-361)
**位置**: `createTerminalSession`
**问题**:
- ResizeObserver 在每次 resize 时都发送 WebSocket 消息
- 可能导致消息风暴
- 没有防抖（debounce）

**影响**: 性能问题，网络拥塞
**修复**: 添加防抖机制

### 10. 没有连接超时处理 (app.js:263-274)
**位置**: WebSocket onopen
**问题**:
- 如果服务器长时间不响应，WebSocket 会一直等待
- 没有连接超时检测
- 用户不知道是否在连接中

**影响**: 用户体验差，资源浪费
**修复**: 添加连接超时和加载指示器

## 中优先级问题 🟡

### 11. 外部依赖使用 CDN (index.html:7, app.js:4-5)
**位置**: HTML 和 JS 导入
**问题**:
- xterm 库从 CDN 加载，可能被篡改
- 如果 CDN 不可用，应用无法使用
- 没有完整性校验（SRI）

```html
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
```

**影响**: 安全风险，可用性问题
**修复**: 本地托管依赖，添加 SRI

### 12. 键盘快捷键冲突 (app.js:447-469)
**位置**: `onKeyDown`
**问题**:
- Ctrl+T 被拦截，与浏览器新标签冲突
- Ctrl+W 被拦截，与浏览器关闭标签冲突
- 可能困扰用户

**影响**: 用户体验问题
**修复**: 使用不同的快捷键或提供配置选项

### 13. 终端主题硬编码 (app.js:222-249)
**位置**: Terminal 初始化
**问题**:
- 主题颜色硬编码在代码中
- 用户无法自定义
- 没有暗色/亮色模式切换

**影响**: 用户体验
**修复**: 允许用户配置主题

### 14. 没有 Session 持久化 (app.js:190-364)
**位置**: `createTerminalSession`
**问题**:
- 页面刷新后所有 session 丢失
- 需要重新连接所有 SSH 会话
- 工作流被打断

**影响**: 用户体验差
**修复**: 使用 sessionStorage 保存 session 元数据

### 15. 没有限制并发连接数 (app.js:190)
**位置**: `createTerminalSession`
**问题**:
- 用户可以创建无限多个终端 session
- 可能导致服务器过载
- 浏览器性能下降

**影响**: 资源耗尽
**修复**: 限制最大并发连接数

## 低优先级问题 🟢

### 16. 没有终端会话管理 UI (app.js)
**问题**: 无法查看所有会话状态、批量关闭等

### 17. 状态栏信息有限 (index.html:308-311, app.js:434-437)
**问题**: 只显示连接状态，没有流量、延迟等信息

### 18. 没有国际化支持 (app.js)
**问题**: 所有文本硬编码英文

### 19. 没有可访问性优化 (index.html)
**问题**: 缺少 ARIA 标签，屏幕阅读器支持差

### 20. CSS 没有响应式设计 (index.html:8-288)
**问题**: 在移动设备上体验差

## 后端相关问题

### 21. 静态文件没有缓存控制 (main.rs:230-252)
**位置**: `static_handler`
**问题**:
- 没有设置 Cache-Control 头
- 每次都重新加载静态文件
- 浪费带宽

**影响**: 性能问题
**修复**: 添加缓存控制头

### 22. 静态文件安全检查不完整 (main.rs:236-238)
**位置**: `static_handler`
**问题**:
- 只检查 `..`、`\` 和开头 `/`
- 没有检查 URL 编码的路径遍历
- 例如 `%2e%2e%2f` 可能绕过检查

**影响**: 路径遍历漏洞
**修复**: 解码 URL 后再检查

### 23. MIME 类型有限 (main.rs:240-245)
**位置**: `static_handler`
**问题**:
- 只支持 js/css/html 三种类型
- 其他文件类型返回 `application/octet-stream`
- 可能导致浏览器处理错误

**影响**: 功能问题
**修复**: 使用更完整的 MIME 类型映射

## 建议改进 📝

### 安全改进
1. **Token 安全**: 使用 HttpOnly cookie 存储 JWT
2. **XSS 防护**: 所有用户输入必须转义
3. **CSP**: 添加 Content-Security-Policy 头
4. **SRI**: 为外部资源添加完整性校验
5. **HTTPS 强制**: 重定向 HTTP 到 HTTPS

### 功能改进
1. **重连机制**: WebSocket 断开后自动重连
2. **连接池**: 复用 WebSocket 连接
3. **离线支持**: Service Worker 缓存静态资源
4. **会话恢复**: 页面刷新后恢复会话
5. **配置面板**: 允许用户自定义设置

### 性能改进
1. **二进制传输**: 使用 ArrayBuffer 替代 base64
2. **防抖**: resize 等频繁操作添加防抖
3. **懒加载**: 按需加载 xterm 库
4. **虚拟滚动**: 终端输出使用虚拟滚动

### 用户体验改进
1. **加载指示器**: 连接时显示加载动画
2. **错误提示**: 友好的错误消息
3. **确认对话框**: 关闭未保存的会话前确认
4. **快捷键提示**: 显示可用快捷键
5. **多语言**: 支持国际化

## 测试建议

### 安全测试
```bash
# 1. 测试 XSS
# 在 host 输入: <img src=x onerror=alert(1)>

# 2. 测试路径遍历
curl -k https://localhost:8443/static/%2e%2e%2fsrc/main.rs

# 3. 测试 token 窃取
# 检查 localStorage 中的 token 是否可被 JS 访问
```

### 功能测试
```bash
# 1. 测试 WebSocket 重连
# 断开网络，然后重新连接

# 2. 测试并发连接
# 打开多个终端标签

# 3. 测试异常输入
# 输入特殊字符、超长字符串等
```

### 性能测试
```bash
# 1. 测试大量输出
# cat 一个大文件

# 2. 测试快速 resize
# 频繁调整窗口大小

# 3. 测试长时间运行
# 保持连接数小时
```

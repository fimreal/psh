# CI/CD 配置指南

## 发布流程

### 自动触发条件

| 事件 | 触发的工作流 |
|------|-------------|
| Push to `main` | ❌ 不触发构建 |
| Pull Request | ✅ 运行测试和构建检查 |
| Push tag `v*` | ✅ 完整构建、测试、发布 |

### 发布新版本

```bash
# 1. 确保代码已提交
git add .
git commit -m "Prepare for release v1.0.0"

# 2. 创建并推送 tag
git tag v1.0.0
git push origin main
git push origin v1.0.0

# 3. 等待 CI/CD 完成
# - 构建二进制文件（4个平台）
# - 构建多架构 Docker 镜像 (epurs/psh)
# - 创建 Gitea Release
# - 上传二进制文件和校验和
```

### 版本号规范

遵循 [语义化版本](https://semver.org/lang/zh-CN/)：

- `v1.0.0` - 正式版本
- `v1.0.0-beta.1` - 预发布版本
- `v1.0.0-rc.1` - 候选版本

## 构建产物

每次 tag 发布会生成以下产物：

**二进制文件**：
- `psh-linux-amd64` + `.sha256`
- `psh-linux-arm64` + `.sha256`
- `psh-darwin-amd64` + `.sha256`
- `psh-darwin-arm64` + `.sha256`

**Docker 镜像**：
- `epurs/psh:<version>`
- `epurs/psh:<major>.<minor>`
- `epurs/psh:latest`

## 本地测试

### 测试构建

```bash
# 本地构建
go build -o psh ./cmd/psh

# 交叉编译
GOOS=linux GOARCH=amd64 go build -o psh-linux-amd64 ./cmd/psh
GOOS=linux GOARCH=arm64 go build -o psh-linux-arm64 ./cmd/psh
GOOS=darwin GOARCH=amd64 go build -o psh-darwin-amd64 ./cmd/psh
GOOS=darwin GOARCH=arm64 go build -o psh-darwin-arm64 ./cmd/psh
```

### 测试 Docker 构建

```bash
# 构建镜像
docker build -t epurs/psh:test .

# 本地运行测试
docker run -d \
  --name psh-test \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=test123 \
  epurs/psh:test

# 测试多架构构建
docker buildx build --platform linux/amd64,linux/arm64 -t epurs/psh:test .
```

## 故障排查

### 构建失败

1. **Go 依赖下载慢**
   - 工作流已配置 GOPROXY 镜像源
   - 本地可设置：`export GOPROXY=https://goproxy.cn,direct`

2. **Docker 推送失败**
   - 检查 Docker Hub 凭证是否正确
   - 确认 `epurs/psh` 仓库有推送权限

### 查看日志

在 Gitea Actions 页面查看详细日志：https://git.epurs.com/gitops/psh/actions

## 相关链接

- [Gitea Actions 文档](https://docs.gitea.com/next/en/actions)
- [语义化版本](https://semver.org/lang/zh-CN/)
- [Docker Hub](https://hub.docker.com/)
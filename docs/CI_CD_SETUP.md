# CI/CD 配置指南

## 配置 Docker Hub

### 1. 获取 Docker Hub 凭证

1. 登录 [Docker Hub](https://hub.docker.com/)
2. 进入 Account Settings -> Security
3. 创建一个新的 Access Token（推荐）或使用密码

### 2. 配置 Gitea Secrets

在你的 Gitea 仓库中配置以下 Secrets：

**路径**：仓库设置 -> Secrets -> Actions

| Secret 名称 | 说明 | 示例 |
|------------|------|------|
| `DOCKER_USERNAME` | Docker Hub 用户名 | `johndoe` |
| `DOCKER_PASSWORD` | Docker Hub 密码或 Access Token | `dckr_pat_xxxx...` |

### 3. 镜像命名规则

推送 tag 后，Docker 镜像会自动推送到：
```
<DOCKER_USERNAME>/psh:<version>
<DOCKER_USERNAME>/psh:latest
```

例如，如果你的用户名是 `johndoe`，打 tag `v1.0.0` 后会生成：
- `johndoe/psh:1.0.0`
- `johndoe/psh:1.0`
- `johndoe/psh:latest`

## 发布流程

### 自动触发条件

| 事件 | 触发的工作流 |
|------|-------------|
| Push to `main` | ❌ 不触发构建 |
| Pull Request | ✅ 运行测试和代码检查 |
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
# - 运行测试
# - 构建多架构 Docker 镜像
# - 创建 GitHub Release
# - 上传二进制文件和校验和
```

### 版本号规范

遵循 [语义化版本](https://semver.org/lang/zh-CN/)：

- `v1.0.0` - 正式版本
- `v1.0.0-beta.1` - 预发布版本（会标记为 pre-release）
- `v1.0.0-rc.1` - 候选版本

## 工作流详解

### Job 依赖关系

```
┌─────────┐  ┌──────┐
│  Build  │  │ Test │
└────┬────┘  └──┬───┘
     │          │
     └──────┬───┘
            │
       ┌────▼────┐
       │ Docker  │ (仅在 tag 时)
       └────┬────┘
            │
       ┌────▼────┐
       │ Release │ (仅在 tag 时)
       └────┬────┘
            │
       ┌────▼────┐
       │ Notify  │ (仅在 tag 时)
       └─────────┘
```

### 构建产物

每次 tag 发布会生成以下产物：

**二进制文件**：
- `psh-linux-amd64.tar.gz` + `.sha256`
- `psh-linux-arm64.tar.gz` + `.sha256`
- `psh-darwin-amd64.tar.gz` + `.sha256`
- `psh-darwin-arm64.tar.gz` + `.sha256`

**Docker 镜像**：
- `<username>/psh:<version>`
- `<username>/psh:<major>.<minor>`
- `<username>/psh:latest`

## 本地测试

### 测试构建

```bash
# 测试特定平台构建
go build -o psh ./cmd/psh

# 交叉编译
GOOS=linux GOARCH=amd64 go build -o psh-linux-amd64 ./cmd/psh
GOOS=linux GOARCH=arm64 go build -o psh-linux-arm64 ./cmd/psh
```

### 测试 Docker 构建

```bash
# 本地构建多架构镜像
docker buildx build --platform linux/amd64,linux/arm64 -t yourusername/psh:test .

# 本地运行测试
docker run -d \
  --name psh-test \
  -p 8443:8443 \
  -v ~/.ssh:/root/.ssh:ro \
  -e PSH_PASSWORD=test123 \
  yourusername/psh:test
```

## 故障排查

### 构建失败

1. **ARM64 交叉编译失败**
   ```bash
   # 安装交叉编译工具链
   sudo apt-get install -y gcc-aarch64-linux-gnu
   ```

2. **Docker 推送失败**
   - 检查 `DOCKER_USERNAME` 和 `DOCKER_PASSWORD` 是否正确
   - 确认 Docker Hub 仓库存在或有创建权限
   - 检查 Access Token 权限

3. **Go 模块下载慢**
   - 工作流已配置 GOPROXY 镜像源

### 查看日志

```bash
# 在 Gitea Actions 页面查看详细日志
# 或使用 CLI 查看特定 job
gh run view <run-id>
```

## 高级配置

### 自定义 Docker Registry

如果需要使用其他 Docker Registry，修改 `.gitea/workflows/build.yml`：

```yaml
- name: Login to Docker Registry
  uses: docker/login-action@v3
  with:
    registry: registry.example.com  # 你的私有仓库
    username: ${{ secrets.DOCKER_USERNAME }}
    password: ${{ secrets.DOCKER_PASSWORD }}

- name: Extract Docker metadata
  uses: docker/metadata-action@v5
  with:
    images: registry.example.com/${{ secrets.DOCKER_USERNAME }}/psh
```

### 添加通知

在 `notify` job 中添加 Slack/Discord 通知：

```yaml
- name: Send Slack notification
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    text: |
      Release ${{ steps.version.outputs.VERSION }}: ${{ steps.status.outputs.status }}
      Docker: ${{ secrets.DOCKER_USERNAME }}/psh:${{ steps.version.outputs.VERSION }}
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
  if: always()
```

## 相关链接

- [Docker Hub](https://hub.docker.com/)
- [语义化版本](https://semver.org/lang/zh-CN/)
- [GitHub Actions 文档](https://docs.github.com/en/actions)

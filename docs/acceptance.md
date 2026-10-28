# mcpanel-node M1 验证记录（acceptance）

状态：M1a 完成轮（2026-09-19）。本文件记录验证命令、环境与结果摘要，
不含任何主机本机路径与凭据。

## 工具链环境

- 构建与测试统一在官方 `golang:1.25` Linux 容器内执行（CGO_ENABLED=0，
  GOFLAGS=-buildvcs=false），宿主机不安装 Go、不修改 PATH。
- 模块与编译缓存使用专属命名卷（用后清理），不影响全局缓存。
- 真实 Docker 只读 stats 集成用例通过挂载 `/var/run/docker.sock`
  （DOCKER_HOST=unix:///var/run/docker.sock）执行。

## 验证命令

```sh
# 全量构建 + vet + 测试（10 包）
docker run --rm -v "$PWD":/app -w /app \
  -v <gomod-cache>:/go/pkg/mod -v <gobuild-cache>:/root/.cache/go-build \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.25 \
  sh -c "go build ./... && go vet ./... && go test ./... -count=1 -timeout 300s"

# 真实 Docker 只读 stats（挂真实 socket）
# ...同上环境，追加 -v /var/run/docker.sock:/var/run/docker.sock
#   go test ./internal/dockerx ./internal/stats -count=1 -v

# 真机冒烟（二进制 serve + wssprobe + 真实 Docker stats）
# ...同上环境：sh scripts/smoke.sh
```

## 结果摘要（M1a 完成轮）

`go build`、`go vet` 零错误；`go test ./... -count=1` 结果：

```text
ok  internal/certutil    0.105s   # 自签证书生命周期/0600/指纹稳定
ok  internal/config      0.009s   # YAML+env 覆盖/校验/无 secret 默认
ok  internal/credential  0.057s   # 0600 原子落盘/熵校验/Load 加固/权限过宽拒绝
ok  internal/dockerx     0.008s   # DOCKER_HOST scheme 管控/统计公式（真实 daemon 用例挂 sock 单独跑）
ok  internal/enroll      15.088s  # pin 先验后发 token/4xx 不重试/5xx 重试/重定向全拒且不泄 Location/错误码
ok  internal/frpc        0.416s   # 进程内真实 frps + 内嵌 frpc 端到端 TLS 隧道（TestTunnelEndToEndTLS PASS）
ok  internal/logutil     0.004s   # secret 脱敏
ok  internal/proto       0.010s   # 信封/seq/错误码/超帧
ok  internal/stats       0.361s   # 协议字段快照/取消/状态归一化/单位换算
ok  internal/wsserver    5.235s   # 握手 401/429/hello 一次/立即+5s stats seq/binary 1003/超帧 1009/会话替换 4000/Shutdown 关会话
```

真机冒烟（隔离容器，loopback 随机端口）：

- `dev-credential`（TEST ONLY）→ `fingerprint` 输出叶证书 pin → `serve`
- wssprobe 经真实 TLS+pin+双握手头完成 `node.hello` req/res（回显
  nodeId/sessionId/caps=["node.hello","node.stats"]/dockerVersion=真实
  daemon 版本），随后立即收到 `evt node.stats` seq=0，字段与协议 §5.2 一致
- 节点结构化日志中 nodeSecret 显示为 `[redacted]`

镜像验证：`docker build -f deploy/Dockerfile` 多阶段构建成功，
`docker run --rm <image> version` 输出 `mcpanel-node 0.1.0`。

## 发布产物

- `dist/mcpanel-node-linux-amd64`、`dist/mcpanel-node-windows-amd64.exe`
  （-trimpath -ldflags "-s -w"），与通过上述全量测试的源码同轮构建；
  `dist/` 在 .gitignore 中，仅本地交付，不入库不推送。

## 明确未验证项（环境受限，非用例失败）

- 真实多级 NAT / UPnP 回探 / 公网直连：需真实公网入口与第二个物理网络；
  本地 compose 双网络仿真只验证隧道拓扑。
- M1b frp 中继的生产授权机制：未实现，特性标记实验性，不在生产启用。


## 0.7.9 回归范围

自动化覆盖：真实 loopback SSH/SFTP 会话进入多级目录、读写/重命名/续传、撤销在用连接、父级符号链接越界拒绝；CPU 0 与非法范围、Docker 创建请求配额字段、显式启动对齐旧配额且启动对账不批量重启。

运行：`go test ./... -count=1`、`go vet ./...`、`go build ./cmd/mcpanel-node`。loopback SFTP 使用真实协议客户端；Docker 请求测试使用本地 HTTP 测试服务。真实外部 SFTP 客户端与生产 Docker 节点升级仍需部署后验收。

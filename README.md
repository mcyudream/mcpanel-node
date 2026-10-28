# mcpanel-node

MC 面板节点守护进程。Go 单二进制；提供 WSS 控制信道服务端（`/control`），
管理面 panel 作为 WebSocket 客户端主动拨入，管理节点上的 Docker 实例。
协议唯一契约：
[`yudream-admin-plugins/docs/mc-panel-protocol-v1.md`](https://github.com/mcyudream/yudream-admin-plugins/blob/main/docs/mc-panel-protocol-v1.md)（本仓不重复定义 schema）。

相关仓库：[YuDream-Admin](https://github.com/mcyudream/YuDream-Admin)（插件式管理平台宿主）·
[yudream-admin-plugins](https://github.com/mcyudream/yudream-admin-plugins)（官方插件，含 mcpanel 面板插件）。

## 0.7.9 本次变更

- SFTP `REALPATH` 按虚拟根返回实际子目录，恢复文件管理器进入多级目录；所有路径复用逐层符号链接边界检查。
- 关闭或到期的 SFTP 会话会断开已经建立的连接，并通过 `ftp.close.live` 能力向面板声明支持撤销在用连接；续传打开文件不再隐式截断内容。
- CPU `0` 通过规格校验，创建容器时省略 `NanoCpus`；正值仍限 100–256000 毫核。存量配额在显式启动或重启时对齐，节点启动对账不因此重启运行中实例。
- 面板 0.24.0 可复用文件通道完成测试副本、覆盖/回退与 CE 资源安装；详见面板仓 `docs/mcpanel-resource-packages.md`。

## 功能概览

- **控制信道**：WSS 服务端 `wss://<node>/control`，面板作为 WebSocket 客户端拨入；
  握手头固定 `Authorization: Bearer <nodeSecret>` + `X-Mcpanel-Node-Id: <nodeId>`，
  常数时间比对，失败泛化 401 + 每 IP 失败预算（超限 429）；单会话语义（新有效连接
  替换旧连接，旧连接关闭码 4000）；帧上限 256KiB（超限断连 1009）。
- **能力声明**：`node.hello` 返回 `caps`（按节点实际启用的能力分组声明：实例/Docker、
  文件、备份、镜像与安装、终端、SFTP、P2P、回收站……），面板据此做方法门禁与功能
  降级；未知方法回 `err proto.unknownMethod`。
- **实例管理**：Docker 容器全生命周期（`instance.create/start/command/delete` 等）、
  控制台输出读取与订阅（`instance.output.*`）、受管容器盘点（`node.containers.list`）、
  端口占用探测（`port.check`）。实例数据固定挂载 `dataDir/instances/<id>`；容器创建
  强制拒 `privileged`/`pid=host`/任意 hostPath/`network=host`，cap drop ALL 仅补
  DAC_OVERRIDE（bind mount 属主错位），另挂 no-new-privileges。
- **文件管理**：实例与节点两级（`file.*` / `node.file.*`）列目录、读、写、新建、
  重命名、删除、打包 zip、解压与分块上传/下载；路径钉死在数据根内（拒绝绝对路径、
  `..` 逃逸与符号链接逃逸），权限类错误带可操作修复指引。
- **备份**：实例级 zip 备份的创建、列举、保留策略清理、恢复、删除、下载与分块上传；
  恢复拒绝 zip-slip，跳过 `.panel-` 临时文件与符号链接。
- **镜像与安装**：`image.list/pull/remove`、`install.run`（服务端安装任务）与
  进度查询 `task.get`。
- **终端与 SFTP**：网页终端 `node.terminal.open/input/close`（含补全探测
  `node.term.complete`）；单端口 SFTP 网关 `ftp.open/close`（按实例签发短时随机
  凭据，默认 2h TTL）。
- **网络与穿透**：frp 内嵌出站隧道（实验，只做 TCP 端到端中继、不终结 TLS）、
  P2P 直连信令与 sidecar（实验）。
- **凭据与注册**：`enroll`/`join` 一次性 token 注册（10 分钟有效）、TLS 叶证书 pin
  （TOFU 或预填校验）、nodeSecret 0600 原子落盘、日志凭据全量脱敏。

## 构建与测试（无全局 Go，容器化工具链）

```sh
# 单元 + 集成测试（Linux 容器；credential 0600 等权限断言依赖 POSIX）
docker run --rm -v "$PWD":/app -w /app \
  -v mcpanel-node-gomod:/go/pkg/mod -v mcpanel-node-gobuild:/root/.cache/go-build \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.25 \
  sh -c "go build ./... && go vet ./... && go test ./... -count=1"

# 真实 Docker 只读 stats 集成（挂 socket）
docker run --rm -v "$PWD":/app -w /app \
  -v mcpanel-node-gomod:/go/pkg/mod -v mcpanel-node-gobuild:/root/.cache/go-build \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.25 \
  sh -c "go test ./internal/dockerx ./internal/stats -count=1 -v"

# 真机冒烟（二进制 serve + wssprobe + 真实 Docker stats）
docker run --rm -v "$PWD":/app -w /app \
  -v mcpanel-node-gomod:/go/pkg/mod -v mcpanel-node-gobuild:/root/.cache/go-build \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.25 sh scripts/smoke.sh

# 发布产物（linux/windows）
docker run --rm -v "$PWD":/app -w /app \
  -v mcpanel-node-gomod:/go/pkg/mod -v mcpanel-node-gobuild:/root/.cache/go-build \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.25 \
  sh -c "mkdir -p dist && go build -trimpath -ldflags='-s -w' -o dist/mcpanel-node-linux-amd64 ./cmd/mcpanel-node && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/mcpanel-node-windows-amd64.exe ./cmd/mcpanel-node"
```

`dist/` 产物仅本地保留（.gitignore），不进仓库。

## 生产接入流程（panel bootstrap 可用后）

**快速路径（0.2.0 起，推荐）——一条命令注册并常驻**：

```sh
mcpanel-node join https://panel.example.com
# 按提示粘贴面板签发的一次性 token（stdin 输入不进 shell history）。
# token 也可用 --token 或 MCNODE_ENROLL_TOKEN 提供；已注册的节点重跑
# join 会跳过注册直接常驻。无需 config.yaml（panel.url 由参数给出）。
```

容器单命令等价（serve 在具备 token + panel.url 时自动注册）：

```sh
docker run -d --name mcpanel-node \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v mcpanel-node-data:/data \
  -p 7443:7443 \
  -e MCNODE_PANEL_URL=https://panel.example.com \
  -e MCNODE_ENROLL_TOKEN=<一次性 token> \
  mcpanel-node:local
# 生产建议用 --env-file（0600 凭据文件）替代 -e 明文。
```

**分步路径（精细控制或已有 config.yaml）**：

```sh
# 0) 准备 config.yaml（参考 configs/config.example.yaml）：
#    panel.url（https 裸 origin）、panel.tlsPinSha256（panel 证书 pin，
#    由管理员在 token 之外提供）或留空走标准 PKIX。

# 1) 打印本节点 TLS 叶证书 SHA-256（首次运行会自动生成自签证书，
#    私钥 0600 落在 dataDir）
mcpanel-node fingerprint --config /etc/mcpanel-node/config.yaml

# 2) 管理员在面板「节点」页录入本节点 endpoint（wss://host[:port]，仅
#    authority），签发一次性 enrollToken（10 分钟有效）。节点 TLS 校验
#    选 pinned 时指纹可留空——注册时以上报的 tlsCertSha256 自动登记
#    （TOFU）；预填指纹则必须相等才消费 token。

# 3) 节点侧发起 bootstrap。token 只应通过环境进入进程，但注意
#    `MCNODE_ENROLL_TOKEN=<值>` 的前缀写法会落入 shell history——用 read -s
#    手工注入（不回显、不进 history），或放入权限 0600 的 envfile 后
#    `set -a; . /etc/mcpanel-node/enroll.env; set +a`，生产建议直接对接
#    secret manager（如 systemd LoadCredential/凭据保管箱）。示例值一律占位。
read -rs MCNODE_ENROLL_TOKEN && export MCNODE_ENROLL_TOKEN   # 粘贴/输入后回车
mcpanel-node enroll --config /etc/mcpanel-node/config.yaml
unset MCNODE_ENROLL_TOKEN

# 4) 启动控制信道服务端，等待 panel 主动拨入
mcpanel-node serve --config /etc/mcpanel-node/config.yaml
```

安全要点：全程 wss/TLS；nodeSecret 仅 bootstrap 响应下发一次，落盘
`dataDir/credential.json`（0600 原子写）；M1 无 rekey，凭据泄露的处置 =
面板删除节点记录并清除本地 credential 后重新 enroll；frp 为实验特性
（M1b），需要节点专属 proxyToken，绝不复用 frps 管理员 token，且隧道只做
端到端 TCP 中继不终结 TLS。

## 容器部署

镜像构建与运行见 `deploy/Dockerfile`、`deploy/compose/node-compose.yml`（节点）
与 `deploy/compose/frps-compose.yml`（M1b 实验中继）。挂载只允许固定的
docker.sock 与 /data 卷；容器内 gopsutil 的资源视图口径限制见下文
「统计口径说明」，`docs/threat-model.md` 有完整威胁边界。

## 跨语言联调入口（Java/Go，无需 panel bootstrap 就绪）

```sh
# 1) 生成测试凭据（TEST ONLY：nodeId 手工指定；secret 随机生成、stdout 一次性
#    输出、不进日志/参数/配置文件）
mcpanel-node dev-credential --node-id <test-node-id> --data-dir /tmp/acceptance

# 2) 输出节点叶证书 pin（panel 侧钉住校验）
mcpanel-node fingerprint --data-dir /tmp/acceptance

# 3) 启动控制信道（随机/固定 loopback 端口）
mcpanel-node serve --data-dir /tmp/acceptance --listen 127.0.0.1:7443

# 4) panel（或本仓探针）拨入验证
scripts/wssprobe -url wss://127.0.0.1:7443 -node-id <test-node-id> \
  -secret <一次性输出> -pin <fingerprint 输出>
```

配置参考 `configs/config.example.yaml`；所有 secret 走环境变量
（`MCNODE_ENROLL_TOKEN` / `MCNODE_FRPC_TOKEN`），示例文件与仓库内不允许出现真实凭据。

## 统计口径说明（重要）

节点以容器形态运行时，gopsutil 读取的是**容器内 proc 视图**：Linux 宿主机上通常
看到宿主机全局 CPU/内存（`/proc` 未隔离），cgroup v2 开启内存限制的部分字段受
容器 quota 影响；磁盘为 dataDir 所在文件系统。面板侧展示不得将其标注为
"节点物理机真实资源"，容器化部署建议按"节点估算资源"呈现。误差口径在 M2 引入
cgroup 精确采集前保持现状。

## 文档

- `docs/threat-model.md` — 威胁边界与信任模型（必读）。
- `docs/acceptance.md` — 验证命令、环境与结果记录。
- 协议本体见 panel 仓 `docs/mc-panel-protocol-v1.md`；本仓不复制 schema。

## 边界（当前不做 / 后续）

- docker-socket-proxy 真隔离（现状：cap drop ALL + no-new-privileges + 固定挂载
  白名单 + 容器创建护栏，socket 挂载本身仍等价宿主 root，见 `docs/threat-model.md`）。
- nodeSecret 轮换（rekey）；凭据泄露的处置 = 面板删除节点记录并清除本地
  credential 后重新 enroll。
- cgroup 精确资源采集（现状见「统计口径说明」）。
- 真实多级 NAT 打洞与 UPnP/IPv6 探测的生产验证（frp 与 P2P 目前为实验特性）。

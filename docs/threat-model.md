# mcpanel-node 威胁边界（M1）

状态：2026-09-19，随 M1a 实现定稿。协议契约以 panel 仓
`docs/mc-panel-protocol-v1.md` 为准，本文件只描述节点侧信任边界与风险接受项。

## 信任模型

```
panel (管理面)  --WSS client-->  node (/control, TLS server)  --只读 API--> docker daemon
     ^                                   ^
     |---- HTTPS bootstrap (node 发起) --|
     |---- frp TCP relay (M1b 实验) ----|
```

- **方向冻结**：只有 node→panel 的 HTTPS bootstrap 出站连接与 frpc 出站隧道；
  面板永远是 WSS 客户端。节点不向任何第三方发起连接（镜像拉取等 M2+ 另评）。
- **控制信道认证**：TLS（自签→面板预录 SHA-256 叶证书 pin；CA→标准 PKIX+hostname）
  + 握手 `Authorization: Bearer` / `X-Mcpanel-Node-Id` 常数时间比对。失败泛化 401，
  不披露哪根头错误；每 IP 失败预算（10 次/分钟）超限 429；拒绝计数有界（≤1024 IP，
  溢出清过期/整体重置）+ 1/s 节流审计日志。
- **帧完整性**：认证后的机密性与完整性完全由 TLS 保证；无逐帧应用层签名
  （协议 v1 已废弃 v0.7 HMAC 方案）。帧上限 256KiB，超限 1009 断连。

## 凭据

| 凭据 | 生命周期 | 存放 |
| --- | --- | --- |
| enrollToken | 一次性、10 分钟、绑定管理员预创建节点记录 | 环境变量 `MCNODE_ENROLL_TOKEN`（优先）或配置；不落盘、不进 URL/日志 |
| nodeSecret | enroll 响应一次性下发；M1 无 rekey，泄露=删节点记录重建 | `dataDir/credential.json`，0600 原子写；Load 校验 regular file/≤16KiB/POSIX 权限；日志恒为 `[redacted]` |
| frp proxyToken | 节点专属（M1b 实验）；绝不复用 frps 管理员 token | controlPlan（credential 内）或 `MCNODE_FRPC_TOKEN`（本地实验） |

- 已注册节点禁止重新 bootstrap 换 key（M1 无 rekey）；`enroll` 命令在凭据已存在
  时直接拒绝。
- `dev-credential` 为 TEST ONLY：nodeId 人工指定，secret 由 `crypto/rand` 生成并
  仅 stdout 一次性输出；生产路径不经过该命令。
- bootstrap 的 TLS 验证必须发生在发送 enrollToken 之前：pin 由管理员在 token 之外
  提供，**永不从响应学习/更新**；panel URL 强制 https 裸 origin（拒 userinfo/
  path/query/fragment/非法端口/明文 http，localdev 也不例外）；HTTP 客户端全拒
  重定向（307/308 不再转发 body，错误信息不包含 Location）。

## Docker 集成

- 代码层只暴露 4 个只读 GET（`_ping`/`version`/`containers/json`/`stats one-shot`），
  自研 stdlib 客户端，无 SDK；DOCKER_HOST 明文 tcp 仅允许 loopback 目标，
  远程/https/npipe 不支持（显式报错）。
- **已知且接受的风险**：挂载 docker.sock 等价于宿主 root 权限（`:ro` 挂载不改变
  socket 语义）。当前缓解 = 容器 cap drop ALL（仅补 DAC_OVERRIDE，见下）+
  no-new-privileges + 固定挂载白名单；真正隔离需 docker-socket-proxy，列为 M2 硬化项。
- **DAC_OVERRIDE 例外（节点容器与实例容器各一处）**：实例数据是 bind mount，文件
  属主由容器内镜像 uid（如 openjdk25 的 10001）与节点侧写入共同决定；root 丢掉
  DAC_OVERRIDE 后按普通用户判 DAC——节点读不了/改不了属主不匹配的文件
  （EACCES/EPERM，且 chmod 自救也 EPERM），实例容器则对节点侧建的 0644/0755 文件
  EACCES 启动即崩。因此两者都补回 DAC_OVERRIDE（其余 cap 仍全丢）。socket 已等价
  宿主 root，该 cap 不扩大实际攻击面（可及路径仍受固定挂载白名单约束），权限类
  错误的对外呈现由 fileutil.PermissionHint 统一附带修复指引。
- 节点为实例创建容器时（M2 起）强制：拒 `privileged`/`pid=host`/任意 hostPath/
  `network=host`（模板白名单除外）、CapDrop ALL + CapAdd DAC_OVERRIDE、
  no-new-privileges、只挂实例 volume 子路径。M1 无此路径。

## frp 隧道（M1b，实验性）

- 端到端 TCP 中继，不终结 TLS（否则 pin 失效）。
- frp token 只隔离本地实验环境，不是生产凭据；生产启用前必须实现面板签发的
  节点专属代理授权。
- frps 侧 dashboard/管理端口不对外；`allowPorts` 限段；入网发布默认绑
  127.0.0.1，公网暴露是显式运维动作。

## 日志与脱敏

- 结构化日志（slog JSON）；nodeSecret/enrollToken/frp token 一律经 `Redact`
  输出 `[redacted]`；enroll 错误不携带响应体；握手拒绝日志 1/s 节流且不含
  凭据。`dist/`、`data/`、`.env` 均在 .gitignore。

## 边界外（明确不做 / 后续）

真实多级 NAT 打洞与 UPnP 回探验证（需真实公网环境，本地 compose 双网络仿真
仅验证隧道拓扑）、M2 容器生命周期护栏、docker-socket-proxy、secret 轮换（rekey）。

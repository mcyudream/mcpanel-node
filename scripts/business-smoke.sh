#!/bin/sh
# 真实 Docker 业务冒烟：在 golang 容器内构建并运行节点 + 面板替身，
# 覆盖 §9 全链路（拉镜像/建实例/启停/控制台/文件/备份/删除）。
set -eu
cd /app

echo "== build node =="
CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -o /tmp/mcpanel-node ./cmd/mcpanel-node

# 数据目录放在仓库挂载内，宿主 Windows 路径经 MCNODE_DATA_HOST_ROOT 告知引擎，
# 使 docker.sock 指向的 Docker Desktop 守护进程能 bind 同一目录。
DATA=/app/.smoke-data
HOST_ROOT="${MCNODE_SMOKE_HOST_ROOT:-D:/code/mcpanel-node/.smoke-data}"
rm -rf "$DATA"
mkdir -p "$DATA"
PORT=7600

echo "== dev credential =="
/tmp/mcpanel-node dev-credential --node-id smoke-node-001 --data-dir "$DATA" | tee "$DATA/cred.txt" >/dev/null
MCNODE_NODE_ID=$(sed -n 's/^nodeId: //p' "$DATA/cred.txt")
MCNODE_NODE_SECRET=$(sed -n 's/^nodeSecret (copy now, shown once, never logged): //p' "$DATA/cred.txt")
[ -n "$MCNODE_NODE_ID" ] && [ -n "$MCNODE_NODE_SECRET" ] || { echo "credential parse failed"; exit 1; }

echo "== fingerprint =="
PIN=$(/tmp/mcpanel-node fingerprint --data-dir "$DATA" | sed -n 's/^sha256://p')
[ -n "$PIN" ] || { echo "fingerprint parse failed"; exit 1; }

echo "== serve =="
MCNODE_LISTEN=127.0.0.1:$PORT MCNODE_DATA_HOST_ROOT="$HOST_ROOT" /tmp/mcpanel-node serve --data-dir "$DATA" > "$DATA/serve.log" 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null || true; for c in $(docker ps -aq --filter label=mcpanel.managed=true 2>/dev/null); do docker rm -f "$c" 2>/dev/null || true; done; rm -rf "$DATA"' EXIT
sleep 2

echo "== business probe =="
PROBE_URL="wss://127.0.0.1:$PORT/control" \
PROBE_PIN="$PIN" \
PROBE_NODE_ID="$MCNODE_NODE_ID" \
PROBE_SECRET="$MCNODE_NODE_SECRET" \
go run ./.acceptance/businessprobe

echo "SMOKE DONE"

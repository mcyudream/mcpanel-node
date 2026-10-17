#!/bin/sh
# 面板业务全链路验收（节点侧）：容器内构建并运行 Go 节点，端口发布到宿主回环，
# 连接参数写入 .panel-smoke-conn.env 供宿主 Java harness 使用。
set -eu
cd /app

CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -o /tmp/mcpanel-node ./cmd/mcpanel-node

DATA=/app/.smoke-data-panel
HOST_ROOT="${MCNODE_SMOKE_HOST_ROOT:-D:/code/mcpanel-node/.smoke-data-panel}"
rm -rf "$DATA"; mkdir -p "$DATA"
PORT="${PANEL_SMOKE_PORT:-7701}"

/tmp/mcpanel-node dev-credential --node-id panel-smoke-001 --data-dir "$DATA" > "$DATA/cred.txt"
NODE_ID=$(sed -n 's/^nodeId: //p' "$DATA/cred.txt")
NODE_SECRET=$(sed -n 's/^nodeSecret (copy now, shown once, never logged): //p' "$DATA/cred.txt")
PIN=$(/tmp/mcpanel-node fingerprint --data-dir "$DATA" | sed -n 's/^sha256://p')
[ -n "$NODE_ID" ] && [ -n "$NODE_SECRET" ] && [ -n "$PIN" ] || { echo "credential parse failed"; exit 1; }

MCNODE_LISTEN=0.0.0.0:$PORT MCNODE_DATA_HOST_ROOT="$HOST_ROOT" /tmp/mcpanel-node serve --data-dir "$DATA" > "$DATA/serve.log" 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null || true; for c in $(docker ps -aq --filter label=mcpanel.managed=true 2>/dev/null); do docker rm -f "$c" 2>/dev/null || true; done; rm -rf "$DATA" "$CONN_OUT"' EXIT
sleep 2

CONN_OUT="${CONN_OUT_FILE:-/app/.panel-smoke-conn.env}"
cat > "$CONN_OUT" <<EOF
PANEL_SMOKE_URL=wss://127.0.0.1:$PORT/control
PANEL_SMOKE_PIN=$PIN
PANEL_SMOKE_NODE_ID=$NODE_ID
PANEL_SMOKE_SECRET=$NODE_SECRET
EOF

echo "node ready, published 0.0.0.0:$PORT; conn env at $CONN_OUT"
echo "waiting ${PANEL_SMOKE_WAIT_SECONDS:-600}s for host java harness ..."
sleep "${PANEL_SMOKE_WAIT_SECONDS:-600}"

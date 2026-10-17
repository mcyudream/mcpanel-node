#!/bin/sh
# 本地测试节点入口：先出 pin（证书自动生成），等 /data/enroll-token.txt 出现后
# 自动 enroll，然后常驻 serve。数据目录挂载为 /data（宿主可见，供 Docker 绑定）。
set -eu
cd /app

mkdir -p /data
BIN=/tmp/mcpanel-node
cp dist/mcpanel-node-linux-amd64 "$BIN"

# 1) 证书 + pin（certutil 自动生成自签证书并输出指纹）
PIN=$("$BIN" fingerprint --data-dir /data | sed -n 's/^sha256://p')
echo "$PIN" > /data/pin.txt
echo "node ready for enrollment; pin=sha256:$PIN"
echo "panel url: ${MCNODE_PANEL_URL:-http://host.docker.internal:8080}"
echo "waiting for enroll token at /data/enroll-token.txt ..."

# 2) 等一次性注册令牌（宿主 UI 创建节点后把 token 写入该文件）
if [ ! -f /data/credential.json ]; then
  while [ ! -s /data/enroll-token.txt ]; do sleep 2; done
  TOKEN="$(head -1 /data/enroll-token.txt | tr -d '\r\n')"
  [ -n "$TOKEN" ] || { echo "enroll token file empty"; exit 1; }
  MCNODE_ENROLL_TOKEN="$TOKEN" "$BIN" enroll --data-dir /data
  : > /data/enroll-token.txt   # 用后即清，防重复使用
  echo "enrolled; starting control channel"
else
  echo "credential exists; skipping enroll"
fi

# 3) 常驻控制信道（发布到宿主 7443）
exec env MCNODE_LISTEN="${MCNODE_LISTEN:-0.0.0.0:7443}" \
  MCNODE_DATA_HOST_ROOT="${MCNODE_DATA_HOST_ROOT:-/app/.dev-node}" \
  "$BIN" serve --data-dir /data

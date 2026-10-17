#!/usr/bin/env sh
# 构建启动器 P2P sidecar 三平台二进制到 dist/（与 mcpanel-node 产物同目录）。
# 用法：sh scripts/build-p2p-sidecar.sh [版本]
set -eu

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist"
mkdir -p "$OUT"

GO="${GO:-}"
if [ -z "$GO" ]; then
  if [ -x "$ROOT/.toolchain/go/bin/go" ]; then
    GO="$ROOT/.toolchain/go/bin/go"
  else
    GO=go
  fi
fi

cd "$ROOT"
echo "==> 构建 mcpanel-p2p sidecar（$VERSION）到 $OUT"
for target in "linux/amd64" "darwin/amd64" "darwin/arm64" "windows/amd64"; do
  os_name="${target%/*}"
  arch="${target#*/}"
  suffix=""
  [ "$os_name" = "windows" ] && suffix=".exe"
  output="$OUT/mcpanel-p2p-${os_name}-${arch}${suffix}"
  echo "--> $target"
  CGO_ENABLED=0 GOOS="$os_name" GOARCH="$arch" "$GO" build \
    -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "$output" ./cmd/mcpanel-p2p
done
ls -lh "$OUT"/mcpanel-p2p-* | awk '{print $9, $5}'
echo "==> 完成（sidecar 只监听 127.0.0.1，启动器读取 stdout 的 MCP2P-READY 行）"

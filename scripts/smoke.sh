#!/bin/sh
# Real-machine smoke test for mcpanel-node (M1a).
#
# Runs inside a Linux container (or any Linux host) with the docker socket
# mounted when Docker stats should be exercised:
#
#   docker run --rm -v "$PWD":/app -w /app \
#     -v mcpanel-node-gomod:/go/pkg/mod -v mcpanel-node-gobuild:/root/.cache/go-build \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -e DOCKER_HOST=unix:///var/run/docker.sock \
#     golang:1.25 sh scripts/smoke.sh
#
# Steps: build -> dev-credential -> fingerprint -> serve (random loopback
# port) -> wssprobe over real TLS -> hello res + immediate node.stats.
set -eu

export CGO_ENABLED=0 GOFLAGS=-buildvcs=false
SMOKE_DIR=$(mktemp -d)
trap 'rm -rf "$SMOKE_DIR"; [ -n "${NODE_PID:-}" ] && kill "$NODE_PID" 2>/dev/null || true' EXIT

echo "== build =="
go build -o "$SMOKE_DIR/mcpanel-node" ./cmd/mcpanel-node
go build -o "$SMOKE_DIR/wssprobe" ./scripts/wssprobe

echo "== test-only credential (entropy enforced, secret printed once below) =="
cd "$SMOKE_DIR"
./mcpanel-node dev-credential --node-id smoke-node-0001 --data-dir . | tee credential.out
NODE_ID=smoke-node-0001
NODE_SECRET=$(sed -n 's/^nodeSecret (copy now, shown once, never logged): //p' credential.out)
test -n "$NODE_SECRET" || { echo "failed to capture secret"; exit 1; }

echo "== fingerprint (pin for the probe) =="
PIN=$(./mcpanel-node fingerprint --data-dir . | head -1 | sed 's/^sha256://')
echo "pin=$PIN"
test ${#PIN} = 64 || { echo "bad pin"; exit 1; }

echo "== serve on random loopback port =="
PORT=$(sh -c 'cat /proc/sys/net/ipv4/ip_local_port_range | head -1 | awk "{print \$1 + 3000}"')
./mcpanel-node serve --data-dir . --listen "127.0.0.1:$PORT" >node.log 2>&1 &
NODE_PID=$!
for i in $(seq 1 50); do
  if grep -q "listening" node.log 2>/dev/null; then break; fi
  sleep 0.2
done
grep -q "listening" node.log || { cat node.log; exit 1; }

echo "== probe (real TLS + handshake + hello + first stats) =="
"$SMOKE_DIR/wssprobe" -url "wss://127.0.0.1:$PORT" \
  -node-id "$NODE_ID" -secret "$NODE_SECRET" -pin "$PIN" -timeout 20s

echo "== node log tail =="
tail -5 node.log
echo "SMOKE OK"

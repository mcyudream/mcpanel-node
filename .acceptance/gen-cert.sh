#!/usr/bin/env sh
# M1 integration acceptance helper (owned by verification agent).
# Generates a self-signed leaf cert/key for the node WSS listener on loopback
# and prints the SHA-256 pin of the DER-encoded leaf cert (lowercase hex),
# which the panel node record must pre-register per protocol v1 section 1.
#
# Usage: sh gen-cert.sh [hostname]   (default: localhost)
# Output: certs/node-{host}.pem / certs/node-{host}-key.pem
set -eu
# Git Bash / MSYS: disable automatic path conversion for -subj /CN=...
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
HOST="${1:-localhost}"
DIR="$(cd "$(dirname "$0")" && pwd)/certs"
CRT="node-$HOST.pem"
KEY="node-$HOST-key.pem"
mkdir -p "$DIR"
cd "$DIR"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT" \
  -days 2 -sha256 \
  -subj "/CN=$HOST" \
  -addext "subjectAltName=DNS:$HOST,IP:127.0.0.1,IP:::1"
echo "cert: $DIR/$CRT"
echo "key:  $DIR/$KEY"
echo "pin (sha256 of DER leaf, lowercase hex):"
openssl x509 -in "$CRT" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1

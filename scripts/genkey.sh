#!/usr/bin/env bash
# 生成 RS256 签名密钥对 (私钥 PEM, .gitignore 已拦 *.pem 永不入库)
# 用法: ./scripts/genkey.sh [输出路径, 默认 ./signing-key.pem]
set -euo pipefail
OUT="${1:-./signing-key.pem}"
if [ -f "$OUT" ]; then
  echo "已存在: $OUT (拒绝覆盖, 换密钥请先手动移走旧的)" >&2
  exit 1
fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT"
chmod 600 "$OUT"
echo "已生成: $OUT (2048-bit RSA, 权限 600)"

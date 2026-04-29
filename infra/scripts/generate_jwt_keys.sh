#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${1:-.}
mkdir -p "$OUT_DIR"
PRIV="$OUT_DIR/private.pem"
PUB="$OUT_DIR/public.pem"

echo "Generating RSA 2048 keypair to $OUT_DIR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PRIV"
openssl rsa -in "$PRIV" -pubout -out "$PUB"

echo "Private: $PRIV"
echo "Public:  $PUB"

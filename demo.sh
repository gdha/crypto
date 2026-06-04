#!/usr/bin/env bash
# demo.sh — demonstrates AES and RSA encrypt/decrypt round-trips
set -euo pipefail

BIN="${BIN:-./crypto}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

AES_KEY="$TMPDIR/demo.key"
RSA_PRIV="$TMPDIR/private.pem"
RSA_PUB="$TMPDIR/public.pem"
PLAINTEXT="Hello from the crypto demo!"

pass() { printf '\033[0;32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '\033[0;31mFAIL\033[0m  %s\n' "$1"; exit 1; }

# ── AES demo ────────────────────────────────────────────────────────────────

echo "=== AES-256-CBC ==="

echo "  Generating AES key file..."
"$BIN" aes-keygen "$AES_KEY" 2>&1 | sed 's/^/  /'

echo "  Encrypting..."
CONTAINER=$(printf '%s' "$PLAINTEXT" | "$BIN" aes-enc "$AES_KEY")
echo "  Container: $CONTAINER"

echo "  Decrypting..."
RESULT=$(printf '%s' "$CONTAINER" | "$BIN" aes-dec "$AES_KEY")

if [ "$RESULT" = "$PLAINTEXT" ]; then
    pass "AES round-trip"
else
    fail "AES round-trip (got: '$RESULT')"
fi

# ── RSA demo ────────────────────────────────────────────────────────────────

echo ""
echo "=== RSA hybrid (EVP_Seal / EVP_Open) ==="

echo "  Generating RSA-2048 key pair..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RSA_PRIV" 2>/dev/null
openssl pkey -in "$RSA_PRIV" -pubout -out "$RSA_PUB" 2>/dev/null
echo "  Keys written to $RSA_PRIV and $RSA_PUB"

echo "  Encrypting with public key..."
CONTAINER=$(printf '%s' "$PLAINTEXT" | "$BIN" rsa-enc "$RSA_PUB")
echo "  Container: ${CONTAINER:0:60}..."

echo "  Decrypting with private key..."
RESULT=$(printf '%s' "$CONTAINER" | "$BIN" rsa-dec "$RSA_PRIV")

if [ "$RESULT" = "$PLAINTEXT" ]; then
    pass "RSA round-trip"
else
    fail "RSA round-trip (got: '$RESULT')"
fi

# ── Cross-check: wrong key must fail ────────────────────────────────────────

echo ""
echo "=== Negative test: decrypt with wrong RSA private key ==="

RSA_WRONG_PRIV="$TMPDIR/wrong_private.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RSA_WRONG_PRIV" 2>/dev/null

if printf '%s' "$CONTAINER" | "$BIN" rsa-dec "$RSA_WRONG_PRIV" > /dev/null 2>&1; then
    fail "Wrong key should not decrypt successfully"
else
    pass "Wrong RSA key correctly rejected"
fi

echo ""
echo "All demo tests passed."

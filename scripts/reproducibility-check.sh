#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "AEGISCHAIN REPRODUCIBLE BUILD VERIFICATION"
echo "Compiling Go binary in two isolated passes (-trimpath)..."
echo "=========================================================="

BUILD_A="dist/repro-a"
BUILD_B="dist/repro-b"

rm -rf "$BUILD_A" "$BUILD_B"
mkdir -p "$BUILD_A" "$BUILD_B"

BINARY="aegischain"

echo "[Pass 1/2] Compiling $BINARY into $BUILD_A..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o "$BUILD_A/$BINARY" ./cmd/aegischain

echo "[Pass 2/2] Compiling $BINARY into $BUILD_B..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o "$BUILD_B/$BINARY" ./cmd/aegischain

HASH_A=$(sha256sum "$BUILD_A/$BINARY" | awk '{print $1}')
HASH_B=$(sha256sum "$BUILD_B/$BINARY" | awk '{print $1}')

echo ""
echo "Build A SHA-256: $HASH_A"
echo "Build B SHA-256: $HASH_B"

if [ "$HASH_A" = "$HASH_B" ]; then
    echo ""
    echo "REPRODUCIBLE BUILD RESULT: PASS"
    echo "Bit-for-bit identical binary artifact produced across independent builds."
    exit 0
else
    echo ""
    echo "REPRODUCIBLE BUILD RESULT: FAIL"
    echo "Binary hash mismatch between Pass 1 and Pass 2."
    exit 1
fi

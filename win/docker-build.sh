#!/usr/bin/env bash
# Runs inside the tracemap-win-build container: cross-compiles the static
# Windows executable into build-win/. The container already sets
# GOOS=windows, CGO_ENABLED=1, the MinGW toolchain and the static Qt flags,
# so this is just the usual `go build`.
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build-win
go build \
    -trimpath \
    -ldflags '-s -w -H=windowsgui' \
    --tags=windowsqtstatic \
    -o build-win/tracemap.exe \
    .

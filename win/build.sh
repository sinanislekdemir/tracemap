#!/usr/bin/env bash
# Host entrypoint: build the Windows cross-compile image (cached after the
# first run) and produce build-win/tracemap.exe. Requires Docker only; nothing
# is installed on the host.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=tracemap-win-build

docker build -t "$IMAGE" win/

# Run as the host user and keep the Go caches on the host so repeated builds
# are fast and build-win/ is not left owned by root.
mkdir -p win/.cache/build win/.cache/mod
docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e GOCACHE=/cache/build \
    -e GOMODCACHE=/cache/mod \
    -v "$PWD:/src" \
    -w /src \
    -v "$PWD/win/.cache/build:/cache/build" \
    -v "$PWD/win/.cache/mod:/cache/mod" \
    "$IMAGE" \
    bash win/docker-build.sh

echo
echo "Done: build-win/tracemap.exe"

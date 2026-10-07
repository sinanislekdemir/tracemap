#!/usr/bin/env bash
# Builds a portable AppImage for tracemap.
#
# Run this on (or inside a container of) the oldest still-supported Ubuntu LTS
# that ships Qt 6.4 (the miqt baseline), so the AppImage only depends on that
# older glibc and runs on every supported distribution. Debian 12 works too and
# is what the release workflow uses. See .github/workflows/release.yml for the
# CI use. Set INSTALL_DEPS=1 to install the toolchain first.
#
# This mirrors poorman's scripts/build-appimage.sh: linuxdeploy plus its Qt
# plugin bundle Qt6 and the app's non-system libraries into one file, and the
# embedded update information lets AppImageUpdate/zsync find new releases.

set -euo pipefail

APP_NAME="tracemap"
ARCH="x86_64"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -n "${VERSION:-}" ]; then
    VERSION="${VERSION#v}"
else
    VERSION="$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || true)"
    VERSION="${VERSION:-0.0.0}"
fi

BIN="build/bin/traceroute"
APPDIR="AppDir"
DESKTOP_FILE="build/linux/tracemap.desktop"
ICON_SRC="build/appicon.png"
OUTPUT="${APP_NAME}-${VERSION}-${ARCH}.AppImage"

# Update information embedded in the AppImage so AppImageUpdate/zsync can find
# new releases. The matching .zsync file must be published next to the AppImage.
UPDATE_INFO="gh-releases-zsync|sinanislekdemir|tracemap|latest|${APP_NAME}-*-${ARCH}.AppImage.zsync"

if [ "${INSTALL_DEPS:-0}" = "1" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        build-essential \
        qt6-base-dev \
        qt6-base-dev-tools \
        pkg-config \
        wget \
        ca-certificates \
        file \
        patchelf \
        libfuse2 \
        desktop-file-utils \
        git
fi

echo "==> Building ${APP_NAME} ${VERSION}"
make build

if [ ! -f "$BIN" ]; then
    echo "Build failed: $BIN not found" >&2
    exit 1
fi

echo "==> Assembling AppDir"
rm -rf "$APPDIR" "$OUTPUT" "${OUTPUT}.zsync"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

install -m 0755 "$BIN" "$APPDIR/usr/bin/${APP_NAME}"
cp "$DESKTOP_FILE" "$APPDIR/usr/share/applications/${APP_NAME}.desktop"
cp "$ICON_SRC" "$APPDIR/usr/share/icons/hicolor/256x256/apps/${APP_NAME}.png"

# linuxdeploy-plugin-qt locates the Qt installation through qmake.
export QMAKE="${QMAKE:-$(command -v qmake6 || command -v qmake || true)}"
if [ -z "${QMAKE:-}" ] || [ ! -x "$QMAKE" ]; then
    echo "qmake not found; install qt6-base-dev-tools (Debian/Ubuntu) first" >&2
    exit 1
fi

if [ ! -f "linuxdeploy-${ARCH}.AppImage" ]; then
    wget -q -O "linuxdeploy-${ARCH}.AppImage" \
        "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-${ARCH}.AppImage"
fi

if [ ! -f "linuxdeploy-plugin-qt-${ARCH}.AppImage" ]; then
    wget -q -O "linuxdeploy-plugin-qt-${ARCH}.AppImage" \
        "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-${ARCH}.AppImage"
fi

chmod +x "linuxdeploy-${ARCH}.AppImage" "linuxdeploy-plugin-qt-${ARCH}.AppImage"

echo "==> Running linuxdeploy"
export OUTPUT
export APPIMAGE_EXTRACT_AND_RUN=1
export LDAI_UPDATE_INFORMATION="$UPDATE_INFO"
export UPDATE_INFORMATION="$UPDATE_INFO"
"./linuxdeploy-${ARCH}.AppImage" \
    --appdir "$APPDIR" \
    --plugin qt \
    --output appimage

if [ ! -f "$OUTPUT" ]; then
    echo "AppImage creation failed: $OUTPUT not found" >&2
    exit 1
fi

if [ ! -f "${OUTPUT}.zsync" ]; then
    echo "WARNING: ${OUTPUT}.zsync was not generated; AppImageUpdate will not work" >&2
fi

echo "==> Created $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
[ -f "${OUTPUT}.zsync" ] && echo "==> Created ${OUTPUT}.zsync"
exit 0

# syntax=docker/dockerfile:1
#
# Cross-compile image for the Windows (x86_64) build of Traceroute Map.
#
# It pairs MinGW-w64 with a statically linked Qt 6.5.3 (the Fsu0413 build that
# MIQT's `windowsqtstatic` target uses), so
# `go build --tags=windowsqtstatic` yields a single self-contained tracemap.exe
# with no Qt DLLs to ship. That keeps the Windows release off a Windows runner;
# the image is cached on GHCR (see .github/workflows/release.yml) and built
# locally with win/build.sh.

# Latest Go 1.26 patch, copied into the build stage below.
FROM golang:1.26 AS go

FROM debian:13

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        pkg-config \
        gcc-mingw-w64-x86-64 \
        g++-mingw-w64-x86-64 \
        mingw-w64-x86-64-dev \
        wget \
        libarchive-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH \
    GOPATH=/go

# Statically linked Qt 6.5.3 for Windows x86_64, built for MinGW GCC 13.2.0.
# The sha256 guard makes the download tamper-evident.
ARG QT_VERSION=6.5.3
RUN wget -q -O /tmp/qt.7z \
        'https://sourceforge.net/projects/fsu0413-qtbuilds/files/Qt6.5/Windows-x86_64/MinGW-GCC/Qt6.5.3-Windows-x86_64-MinGW13.2.0-msvcrt-staticFull-20240527.7z' \
    && echo '66684817adc07ff746e8f6b5d9225ea76899940876c3f6f8392df0b0a750544f  /tmp/qt.7z' | sha256sum -c \
    && mkdir -p /qt/${QT_VERSION} \
    && bsdtar xf /tmp/qt.7z -C /tmp \
    && mv /tmp/Qt6.5.3-Windows-x86_64-MinGW13.2.0-msvcrt-staticFull /qt/${QT_VERSION}/mingw_64 \
    && rm /tmp/qt.7z

# The Fsu0413 archive ships no pkg-config files, and MIQT resolves Qt through
# `pkg-config --cflags --libs Qt6Widgets`, so provide the four module files.
COPY pkgconfig/ /qt/6.5.3/mingw_64/lib/pkgconfig/

ENV CXX=x86_64-w64-mingw32-g++ \
    CC=x86_64-w64-mingw32-gcc \
    PKG_CONFIG_PATH=/qt/6.5.3/mingw_64/lib/pkgconfig \
    CGO_ENABLED=1 \
    GOOS=windows \
    GOARCH=amd64

# Qt 6.0 < 6.7 needs extra resource objects linked in when statically linking
# (QTBUG-91448); -Wl,--allow-multiple-definition suppresses the duplicate
# symbols that pulling them in would otherwise cause.
ENV CGO_LDFLAGS='-static -lwtsapi32 -luxtheme -lole32 -lwinpthread -lsynchronization -loleaut32 -lws2_32 -luuid -luser32 -ladvapi32 -lshlwapi -lnetapi32 -ldxgi -ld3d9 -ld3d11 -ld3d12 -ldwrite -lwinmm -lmincore -lshcore -limm32 -lgdi32 -lcomdlg32 -ldwmapi -lauthz -lversion -lsetupapi -L/qt/6.5.3/mingw_64/lib/ -lQt6BundledZLIB -lQt6BundledPcre2 -lQt6BundledLibpng -lQt6BundledHarfbuzz -lQt6BundledFreetype -L/qt/6.5.3/mingw_64/plugins/styles -lqwindowsvistastyle -L/qt/6.5.3/mingw_64/plugins/platforms -lqwindows -Wl,--allow-multiple-definition /qt/6.5.3/mingw_64/lib/objects-Release/QWindowsIntegrationPlugin_resources_1/.rcc/qrc_openglblacklists.cpp.obj /qt/6.5.3/mingw_64/lib/objects-Release/QWindowsIntegrationPlugin_resources_2/.rcc/qrc_cursors.cpp.obj /qt/6.5.3/mingw_64/lib/objects-Release/Widgets_resources_1/.rcc/qrc_qstyle.cpp.obj /qt/6.5.3/mingw_64/lib/objects-Release/Widgets_resources_3/.rcc/qrc_qmessagebox.cpp.obj /qt/6.5.3/mingw_64/lib/objects-Release/Gui_resources_1/.rcc/qrc_qpdf.cpp.obj'

WORKDIR /src
CMD ["win/docker-build.sh"]

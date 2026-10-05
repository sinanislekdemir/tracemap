# Windows cross-build

Windows is not built on a Windows runner. `win/Dockerfile` is a MinGW-w64
cross-compile image with a **statically linked Qt 6.5.3** (the Fsu0413 build
that MIQT's `windowsqtstatic` target uses), so `go build --tags=windowsqtstatic`
produces a single self-contained `tracemap.exe` with no Qt DLLs to ship.

This follows the same approach as the `recovery-qt` project: a dedicated,
cached Docker image keeps the toolchain off the host, and the release workflow
publishes the image to GHCR so later runs reuse its layers.

## Build

```sh
./win/build.sh
```

The first run builds the image (downloads ~1 GB of Qt and installs the MinGW
toolchain); later runs reuse it and the host-mounted Go caches. The result is
`build-win/tracemap.exe`.

The release workflow (`.github/workflows/release.yml`, job `build-windows`) does
the same on `ubuntu-24.04` and packages `tracemap-<version>-windows-amd64.zip`.

## Layout

- `Dockerfile` — the MinGW-w64 + static Qt6 cross-compile image
- `pkgconfig/` — the `Qt6{Platform,Core,Gui,Widgets}.pc` files the Fsu0413
  archive is missing (MIQT resolves Qt through `pkg-config`)
- `docker-build.sh` — runs inside the container (`go build`)
- `build.sh` — host entrypoint (`docker build` + `docker run`)

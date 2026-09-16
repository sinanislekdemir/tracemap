# tracemap

[![CI](https://github.com/sinanislekdemir/tracemap/actions/workflows/ci.yml/badge.svg)](https://github.com/sinanislekdemir/tracemap/actions/workflows/ci.yml)

**A desktop traceroute visualizer.** tracemap runs `traceroute`/`tracert` from
your own machine, geolocates every responsive hop, and draws the path on an
interactive world map. It can resolve a domain's DNS records and trace every
address it finds, save completed traces to a local database, and replay any
selection back onto the map to compare routes and spot shared hops.

Built with [Wails v2](https://wails.io) — a Go backend bound directly to a
React + TypeScript frontend, packaged as a single native binary.

## Screenshots

<img width="1827" height="1047" alt="image" src="https://github.com/user-attachments/assets/7c2936ef-f6d0-4ddc-8113-8767712c2026" />

*Tracing a host: live hop list, per-hop RTT/ASN, and the path drawn on the map.*
<img width="2109" height="1160" alt="image" src="https://github.com/user-attachments/assets/40c55a08-f2dd-472d-bf61-3d126213fdcf" />


<img width="2109" height="1160" alt="image" src="https://github.com/user-attachments/assets/89df3ba7-79c8-40ac-b2e6-5867a9a504a2" />

*Loading several saved traces at once; hops shared by two or more paths are
highlighted as correlation points.*

## Features

- **Single trace** — enter a hostname or IP, stream hops into the UI as they
  arrive, and watch the path build on the map.
- **Advanced scan** — resolve a domain's `A`/`AAAA`/`CNAME`/`MX`/`NS` records
  and trace every address found, each in its own colour with a legend.
- **Geolocation** — every responsive hop is resolved to coordinates, city,
  country and ASN/ISP, with a persistent cache so repeat hops are instant.
- **History** — explicitly save completed traces and scans to a local SQLite
  database, then browse, replay, delete or clear them.
- **Comparison & correlation** — load a selection of saved traces onto one map;
  hops that appear in two or more traces are marked as shared.
- **Cancel** — abort a running trace or scan at any time.
- **Offline-friendly** — an optional local GeoLite2 database is used as a
  fallback when the remote geolocation service is unavailable.

## Platforms

Prebuilt binaries are attached to each tagged release:

| OS | Architecture | Artifact |
| --- | --- | --- |
| Linux | x86_64 | `tracemap-<version>-linux-amd64.tar.gz` |
| macOS | Universal (Intel + Apple Silicon) | `tracemap-<version>-darwin-universal.zip` |
| Windows | x86_64 | `tracemap-<version>-windows-amd64.zip` |

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which builds each
target on its native runner and publishes a GitHub release. Wails apps cannot
be cross-compiled, so every platform is built on its own runner. CI
(`.github/workflows/ci.yml`) runs `make check` on every push and pull request.

## How it works

Raw ICMP sockets are not available to the webview, and the point is to measure
**your** network path, so the Go backend runs the system `traceroute`/`tracert`
binary locally and streams parsed hops to the UI. There is no HTTP server or
WebSocket: the backend is linked into the app and exposed to the frontend
through Wails bindings and runtime events.

```
Wails window (React + Leaflet map UI)
   │  Bind: Trace, Scan, Cancel, SaveHistory, ListHistory, LoadHistory, …
   │  Events: trace:hop, trace:geo, trace:done, scan:targets, …
   ▼
Go backend (in-process)
   ├── tracerouter  spawn system traceroute/tracert, parse output
   ├── geolocator   IP → lat/lon, city, country, ASN (remote + SQLite + mmdb)
   ├── dnscheck     A/AAAA/CNAME/MX/NS lookup → trace targets
   └── history      saved traces/scans (SQLite snapshot store)
```

Every trace event carries a `target` id so the UI can group and colour
concurrent traces (`0` is the single-trace view; a scan assigns `1..N`).

## Requirements

- **Go** 1.26+
- **Node.js** and **npm**
- **Wails CLI**: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- **Linux system packages** (Fedora): `gcc-c++ gtk3-devel webkit2gtk4.1-devel`
  - Debian/Ubuntu: `gcc g++ libgtk-3-dev libwebkit2gtk-4.1-dev`
- A system traceroute tool: `traceroute` (Linux/macOS), or a fallback of
  `tracepath`/`mtr`; Windows ships `tracert`. tracemap discovers the first one
  available on `PATH` or at conventional install locations.

Run `make sysdeps` to verify the Linux build/runtime dependencies.

## Build & run

Everything goes through the `Makefile`. On Linux the build needs the
`webkit2_41` tag; the Makefile auto-detects it, so just use `make`.

```sh
make dev          # hot-reload dev app
make build        # release binary -> build/bin/traceroute
make run          # build then launch
make check        # go vet + go test + tsc --noEmit
make bindings     # regenerate frontend/wailsjs from the Go bound methods
make sysdeps      # verify Linux build/runtime dependencies
make clean        # remove build/bin, frontend/dist
```

## Usage

1. Type a hostname or IP into **TARGET / DOMAIN** and press **Trace**
   (or `Enter`).
2. Press **Scan** to resolve all DNS records for the domain and trace each
   address. Each target gets its own colour in the legend and hop list.
3. Press `Esc` or **Cancel** to stop a running operation.
4. Press **+ History** to save the current view, and **History** to browse
   saved entries.

Hops that have no coordinates (private addresses, geolocation misses) stay in
the hop list but are omitted from the map. The target address is always shown
as the final entry, even if the trace never reaches it.

## History & comparison

- **Saving is explicit** — nothing is stored until you choose **+ History**.
- The **History** modal lists every saved entry with its kind, target, path
  count, hop count and timestamp. Select one or more entries and choose
  **Show on map** to replay them in the main view.
- In history view, the app bar shows `HISTORY · N paths`, and an **EXIT**
  button returns to the live view (running a new trace does too).
- Hops present in two or more traces are highlighted as **shared** on the map
  and badged in the hop list — the quickest way to spot common paths and
  correlation points.
- Entries can be deleted individually or all at once.

## Configuration

All configuration is via environment variables.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRACEROUTE_DB` | `tracemap.db` | SQLite database holding the geo cache and history; `off` disables persistence. |
| `TRACEROUTE_GEOIP_CITY_DB` | auto-detected | Path to `GeoLite2-City.mmdb`. |
| `TRACEROUTE_GEOIP_ASN_DB` | auto-detected | Path to `GeoLite2-ASN.mmdb`. |
| `TRACEROUTE_GEOIP_DIR` | `/usr/share/GeoIP` etc. | Directory to search for GeoLite2 databases. |

The database is written **next to the binary** when that directory is
writable, otherwise under `~/.cache/traceroute/`. It contains two tables:
`geo_cache` (geolocation replies) and `history_entry` (saved traces/scans).

Geolocation resolution order: in-memory cache → SQLite cache → `ipwho.is`
(source of truth, throttled to 2 req/s) → local GeoLite2 `.mmdb` fallback.
Only remote replies are cached.

## Development

```
main.go                     Wails entry; embeds frontend/dist; window options
app.go                      App struct, bound methods, events
internal/tracerouter/       spawn system traceroute/tracert, parse output
internal/geolocator/        IP → geo (remote-first, SQLite cache, mmdb fallback)
internal/dnscheck/          A/AAAA/CNAME/MX/NS lookup → trace targets
internal/history/           saved traces/scans (SQLite snapshot store)
frontend/src/               React app
frontend/wailsjs/           generated bindings — do not edit by hand
```

### Testing

- Go tests live beside their packages and are table-driven.
- `tracerouter` tests use a fake shell binary — no real traceroute.
- `dnscheck` tests use a fake resolver — no network.
- `geolocator` tests use fake lookups/stores; real-database tests skip when
  absent.
- `history` tests use a temporary SQLite file — no network.

Run everything with:

```sh
make check
```

## Security

- Targets are strictly validated (`tracerouter.validateTarget`) and passed to
  `exec` as an argument array — user input is never interpolated into a shell
  string.
- No secrets or credentials are stored; all data stays in local SQLite files.

## License

[MIT](LICENSE) © 2026 Sinan Islekdemir

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
<img width="1280" height="777" alt="Screenshot_2026-09-17_20-45-35" src="https://github.com/user-attachments/assets/42072f92-fe50-4048-8282-e07544bf61a1" />
<img width="1280" height="777" alt="Screenshot_2026-09-17_20-47-13" src="https://github.com/user-attachments/assets/936e8436-c2a7-4370-8931-a57c2a5d474f" />
<img width="1280" height="777" alt="Screenshot_2026-09-17_20-47-56" src="https://github.com/user-attachments/assets/c5575b5b-81f8-4f79-8c90-68393af7277a" />
<img width="1280" height="777" alt="Screenshot_2026-09-17_20-53-43" src="https://github.com/user-attachments/assets/a9acbc7c-81cf-4afa-be73-7ff1530f298a" />
<img width="1280" height="777" alt="Screenshot_2026-09-17_20-48-37" src="https://github.com/user-attachments/assets/d0ceee12-6889-4124-8ee1-68d2d3d70042" />


*Loading several saved traces at once; hops shared by two or more paths are
highlighted as correlation points.*

## Features

- **Single trace** — enter a hostname or IP, stream hops into the UI as they
  arrive, and watch the path build on the map.
- **Advanced scan** — resolve a domain's `A`/`AAAA`/`CNAME`/`MX`/`NS`/`SOA`
  records and trace every address found, each in its own colour with a legend.
  The scan follows `NS` records and the SOA primary nameserver, resolving each
  nameserver host's own addresses recursively up to a bounded depth, so
  nameserver infrastructure is traced too.
- **Subdomain discovery** — the Scan dialog can brute-force 1000+ common labels
  (with wildcard filtering), reverse-resolve (PTR) discovered IPs, sweep `/24`
  netblocks, and extract hosts from SPF/DMARC TXT and SRV records. Results are
  cached locally and can be reviewed and traced selectively.
- **Port scanning** — right-click a target or hop and choose **Find open ports**.
  The pure-Go scanner (no nmap) does a TCP connect scan or best-effort UDP
  probe over common-port presets or a custom range, with randomised port order
  and jitter to reduce the scan signature. Open ports are optionally identified
  by banner grab, HTTP request and TLS handshake (server, certificate and ALPN).
- **Geolocation** — every responsive hop is resolved to coordinates, city,
  country and ASN/ISP, with a persistent cache so repeat hops are instant.
- **History** — explicitly save completed traces and scans to a local SQLite
  database, then browse, replay, delete or clear them.
- **Comparison & correlation** — load a selection of saved traces onto one map;
  hops that appear in two or more traces are marked as shared.
- **Collapsible panels** — click a splitter to fold the hop list or the DNS /
  subdomain panel away and give the space to the map; the collapsed panel leaves
  a slim rail with a chevron to bring it back. Drag a splitter to resize it.
- **Live console** — a collapsible, resizable bottom console logs every hop,
  geolocation and scan event with a timestamp and severity, and can be cleared.
- **Missing-dependency guidance** — if no `traceroute`/`tracepath`/`mtr` (Unix)
  or `tracert` (Windows) is installed, the app shows a modal with the install
  command for your platform instead of a bare error.
- **Cancel** — abort a running trace or scan at any time.
- **Offline-friendly** — an optional local GeoLite2 database is used as a
  fallback when the remote geolocation service is unavailable.

## Platforms

Prebuilt binaries are attached to each tagged release:

| OS | Architecture | Artifact |
| --- | --- | --- |
| Linux | x86_64 | `tracemap-<version>-linux-amd64.tar.gz`, `.deb`, `.rpm` |
| macOS | Universal (Intel + Apple Silicon) | `tracemap-<version>-darwin-universal.zip` |
| Windows | x86_64 | `tracemap-<version>-windows-amd64.zip` |

The `.deb` and `.rpm` packages install the binary as `tracemap` (to `/usr/bin`),
a desktop entry and an icon.

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
   │  Bind: Trace, Scan, ScanPorts, CheckTools, Cancel, SaveHistory, ListHistory, …
   │  Events: trace:hop, trace:geo, trace:done, scan:targets, portscan:open, …
   ▼
Go backend (in-process)
   ├── tracerouter  spawn system traceroute/tracert, parse output
   ├── geolocator   IP → lat/lon, city, country, ASN (remote + SQLite + mmdb)
   ├── dnscheck     A/AAAA/CNAME/MX/NS/SOA lookup → trace targets
   ├── subdomains   local subdomain discovery (brute force, PTR, SPF/SRV)
   ├── portscan     TCP connect / UDP port scan + banner/HTTP/TLS probing
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
  available on `PATH` or at conventional install locations. If none is found,
  the app opens a modal with the install command for your platform.

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
2. Press **Scan** to open the scan options (DNS records, subdomain discovery,
   and whether to auto-trace or review). Each target gets its own colour in the
   legend and hop list. Discovered subdomains appear in the **SUBDOMAINS** pane,
   where you can select which ones to trace.
3. Press **Ports** in the toolbar to scan the target, or right-click a target in
   the **TARGETS** pane, a hop in the hop list, or a marker on the map and
   choose **Find open ports**. Pick **Common ports** (Top 20/100/1000) or a
   **Port range**, choose TCP or UDP, and optionally identify protocols. Open
   ports stream into the dialog as they are found.
4. Click a splitter between the map and a side panel to collapse or expand that
   panel — handy when you want more room for the map. Drag the splitter to
   resize instead.
5. Press `Esc` or **Cancel** to stop a running operation.
6. Press **+ History** to save the current view, and **History** to browse
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

The database lives in the per-user config directory:
`~/.config/traceroute/tracemap.db` on Linux,
`~/Library/Application Support/traceroute/tracemap.db` on macOS, and
`%AppData%\traceroute\tracemap.db` on Windows. It contains three tables:
`geo_cache` (geolocation replies), `history_entry` (saved traces/scans) and
`subdomain` (discovered subdomains).

Geolocation resolution order: in-memory cache → SQLite cache → `ipwho.is`
(source of truth, throttled to 2 req/s) → local GeoLite2 `.mmdb` fallback.
Only remote replies are cached.

## Development

```
main.go                     Wails entry; embeds frontend/dist; window options
app.go                      App struct, bound methods, events
internal/tracerouter/       spawn system traceroute/tracert, parse output
internal/geolocator/        IP → geo (remote-first, SQLite cache, mmdb fallback)
internal/dnscheck/          A/AAAA/CNAME/MX/NS/SOA lookup → trace targets
internal/subdomains/        local subdomain discovery (brute force, PTR, SPF/SRV)
internal/portscan/          TCP connect / UDP port scan + banner/HTTP/TLS probing
internal/history/           saved traces/scans (SQLite snapshot store)
internal/appdata/           shared SQLite database path (tracemap.db)
frontend/src/               React app
frontend/wailsjs/           generated bindings — do not edit by hand
```

### Testing

- Go tests live beside their packages and are table-driven.
- `tracerouter` tests use a fake shell binary — no real traceroute.
- `dnscheck` tests use a fake resolver — no network.
- `subdomains` tests use a fake resolver and a temp SQLite cache — no network.
- `geolocator` tests use fake lookups/stores; real-database tests skip when
  absent.
- `history` tests use a temporary SQLite file — no network.
- `portscan` tests scan localhost listeners and `httptest` HTTP/TLS servers —
  no external network.

Run everything with:

```sh
make check
```

## Security

- Targets are strictly validated (`tracerouter.validateTarget`) and passed to
  `exec` as an argument array — user input is never interpolated into a shell
  string.
- Port scanning dials the host directly from the Go standard library; no shell
  is involved and only open ports are reported. Scan only hosts you are
  authorised to test.
- No secrets or credentials are stored; all data stays in local SQLite files.

## License

[MIT](LICENSE) © 2026 Sinan Islekdemir

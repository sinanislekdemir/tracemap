# AGENTS.md

Traceroute Map — a **Wails v2 desktop app** (Go backend + React/TypeScript
frontend) that runs traceroutes from the local machine and draws them on a map.

## Commands

Everything goes through the `Makefile`. On Linux the build needs the
`webkit2_41` tag; the Makefile auto-detects it, so just use `make`.

```sh
make dev          # hot-reload dev app
make build        # release binary -> build/bin/traceroute
make run          # build then launch
make check        # go vet + go test + tsc --noEmit  (run before finishing)
make test         # Go tests only
make typecheck    # frontend type-check only
make bindings     # regenerate frontend/wailsjs from the Go bound methods
make sysdeps      # verify Linux build/runtime dependencies
make clean        # remove build/bin, frontend/dist
```

System packages (Fedora): `gcc-c++ gtk3-devel webkit2gtk4.1-devel`.
Wails CLI: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`.

Always run `make check` after changes. Never commit unless asked.

## Layout

```
main.go                     Wails entry; embeds frontend/dist; window options
app.go                      App struct, bound methods (Trace/Scan/ScanPorts/Cancel/History), events
internal/tracerouter/       spawn system traceroute/tracert, parse output
internal/geolocator/        IP -> geo (remote-first, SQLite cache, mmdb fallback)
internal/dnscheck/          A/AAAA/CNAME/MX/NS lookup -> trace targets
internal/subdomains/        local subdomain discovery (brute force, PTR, SPF/SRV)
internal/portscan/          TCP connect / UDP port scan + banner/HTTP/TLS probing
internal/history/           saved traces/scans (SQLite snapshot store)
internal/appdata/           shared SQLite database path (tracemap.db)
frontend/src/               React app
frontend/wailsjs/           generated bindings — do not edit by hand
build/                      Wails build assets (appicon.png, platform files)
.github/workflows/          CI (make check) + tag-triggered release builds
PLAN.md                     design/architecture document
```

## Architecture notes

- **Backend is in-process.** There is no HTTP server or WebSocket. The Go code
  is bound to the frontend via Wails; progress is streamed as runtime events.
- **Every trace event carries a `target` id.** `0` is the single-trace view;
  `Scan` assigns `1..N` to the addresses it traces, so the UI can group and
  colour concurrent traces.
- **Advanced scan** (`App.Scan`): resolve the domain's records (including SOA
  via a raw query — `net.Resolver` has no SOA method), expand them by following
  `NS` hostnames and the SOA primary nameserver recursively (`dnscheck.Expand`,
  bounded by `MaxNSDepth`/`maxNSHosts`), emit `scan:records` then `scan:targets`,
  trace each address with bounded concurrency (`scanConcurrency`), then
  `scan:done`. IPv6 targets are dropped when the host has no global IPv6 address
  (`filterUnroutable`).
- **Traceroute tool discovery** (`internal/tracerouter`): picks the first of
  `traceroute`, `tracepath`, `mtr` (Unix) or `tracert` (Windows) found on `PATH`
  or at conventional absolute paths, then builds tool-specific flags. The parser
  auto-detects traceroute/tracert/tracepath/mtr line formats and merges
  tracepath's repeated per-probe lines. Set `Runner.Binary` to override.
- **Geo resolution order** (`internal/geolocator`): in-memory cache → SQLite
  cache → `ipwho.is` (source of truth, throttled to 2 req/s) → local GeoLite2
  `.mmdb` fallback. Only remote replies are cached. Local hits without
  coordinates are treated as misses.
- **Database location** (`internal/appdata`): a single `tracemap.db` holds the
  `geo_cache`, `history_entry` and `subdomain` tables. It lives in the per-user
  config directory (`~/.config/traceroute/` on Linux,
  `~/Library/Application Support/traceroute/` on macOS, `%AppData%\traceroute\`
  on Windows), so it is independent of where the binary runs. Env override
  `TRACEROUTE_DB` (`off` disables all persistence). GeoLite2 paths:
  `TRACEROUTE_GEOIP_CITY_DB`, `TRACEROUTE_GEOIP_ASN_DB`,
  `TRACEROUTE_GEOIP_DIR`.
- **Subdomain discovery** (`internal/subdomains`): local-DNS only. `Discover`
  detects wildcards, brute-forces the embedded 1000+-name `Wordlist`, reverse-
  resolves discovered IPs (optionally sweeping `/24`s), and extracts hosts from
  SPF/DMARC TXT and SRV records. Bounded concurrency + rate limiter; results are
  cached in the `subdomain` table via `Store` (implements `Cache`). The Scan
  dialog (`ScanOptions`) chooses which techniques run; `App.Scan` emits
  `scan:subdomains`/`scan:progress`, and `App.TraceTargets` traces a reviewed
  selection.
- **Port scanning** (`internal/portscan`): pure-Go, no nmap. `App.ScanPorts`
  expands a preset (`top20`/`top100`/`top1000`) or a `ParsePorts` range into a
  port list, then `Scanner.Scan` probes with bounded concurrency, randomised
  port order and jitter. TCP uses a connect scan; UDP sends a protocol-specific
  datagram and reports only replies (best-effort). Optional `Probe` identifies
  the service by banner grab, HTTP `GET`/`Server` header, or TLS handshake
  (cert CN/SAN, issuer, ALPN); on unknown ports TLS is tried before HTTP because
  an HTTP server answers a TLS ClientHello with a misleading plaintext `400`.
  Events: `portscan:open`, `portscan:progress`, `portscan:done`,
  `portscan:error`; results are not persisted. `ScanPorts` uses the shared
  `App.begin()` cancel model, so it cancels (and is cancelled by) other
  operations.
- **History** (`internal/history`): explicit snapshots of completed traces/scans
  in the shared `tracemap.db` (JSON blob per entry + denormalized counts).
  Bound methods: `SaveHistory`, `ListHistory`, `LoadHistory`,
  `DeleteHistory`, `ClearHistory`. The frontend builds the snapshot (it holds the
  async geo results); nothing is saved automatically.
- **Shared-hop correlation** is computed in the frontend (`App.tsx`): IPs present
  in 2+ traces become `sharedHops`, highlighted on the map and in the hop list.

## Frontend conventions

- **No page scrolling.** The app is a fixed `100vh` grid (app bar → toolbar →
  sidebar/splitter/map → status bar). Only panes scroll internally.
- **react-leaflet gotcha:** `className` must be a **top-level prop** on
  `CircleMarker`/`Polyline`. Putting it in `pathOptions` routes it through
  `setStyle()`, which silently drops it. Colours go in `pathOptions`; animations
  go in `className` + CSS.
- **Trace colours** come from `src/colors.ts`, assigned by target index.
- **History view**: `HistoryModal` lists saved entries; loading selection
  replaces the main map's traces with fresh contiguous ids/colours and sets
  `viewMode='history'` (exited by running a new trace or the app-bar EXIT).
- `buildDisplayHops()` (`src/traces.ts`) appends/marks the resolved target IP as
  the final list entry; `isLocated()` treats `(0, 0)` as "no coordinates".
- **Port scan entry points**: the toolbar **Ports** button opens `PortScanModal`
  for the current target. The right-click context menu (`ContextMenu.tsx`, a
  generic cursor menu raised by `HopList`, `TraceList` and the map markers)
  offers **Find open ports** for a specific IP. The modal goes options → live
  results, owns its own `portscan:*` subscriptions, and streams results in
  place. Do not add a `window` `contextmenu` listener to close the menu — it can
  fire for the same event that opened it; `pointerdown`/`blur`/`Escape` suffice.
- After adding or renaming a bound Go method, run `make bindings` or the
  frontend imports will not compile.

## Testing

- Go tests live beside their packages; use table-driven style.
- `tracerouter` tests use a fake shell binary via `Runner.Binary`.
- `dnscheck` tests use a fake `Resolver` — no real network.
- `geolocator` tests use fake lookups/stores; real-DB tests skip when absent.
- `history` tests use a temp-file SQLite store; no network.
- `subdomains` tests use a fake resolver and a temp SQLite cache; no network.
- `portscan` tests scan localhost listeners and `httptest` HTTP/TLS servers; no
  external network. `Scanner.DialContext`/`ResolveIP` can be faked.
- Keep tests deterministic and offline.

## Security

- Never interpolate user input into a shell string. Targets are validated by
  `tracerouter.validateTarget` and passed to `exec` as an argument array.
- Port scanning dials the host from the Go standard library only (no shell); it
  reports only open ports and never sends credentials.

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
app.go                      App struct, bound methods (Trace/Scan/Cancel/History), events
internal/tracerouter/       spawn system traceroute/tracert, parse output
internal/geolocator/        IP -> geo (remote-first, SQLite cache, mmdb fallback)
internal/dnscheck/          A/AAAA/CNAME/MX/NS lookup -> trace targets
internal/history/           saved traces/scans (SQLite snapshot store)
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
- **Advanced scan** (`App.Scan`): resolve the domain's records, emit
  `scan:records` then `scan:targets`, trace each address with bounded
  concurrency (`scanConcurrency`), then `scan:done`. IPv6 targets are dropped
  when the host has no global IPv6 address (`filterUnroutable`).
- **Geo resolution order** (`internal/geolocator`): in-memory cache → SQLite
  cache → `ipwho.is` (source of truth, throttled to 2 req/s) → local GeoLite2
  `.mmdb` fallback. Only remote replies are cached. Local hits without
  coordinates are treated as misses.
- **Cache location**: `geo-cache.db` next to the binary, falling back to
  `~/.cache/traceroute/` when that directory is not writable. Env overrides:
  `TRACEROUTE_GEOIP_CACHE` (`off` disables), `TRACEROUTE_GEOIP_CITY_DB`,
  `TRACEROUTE_GEOIP_ASN_DB`, `TRACEROUTE_GEOIP_DIR`.
- **History** (`internal/history`): explicit snapshots of completed traces/scans
  in `history.db` (JSON blob per entry + denormalized counts), stored next to the
  binary or in `~/.cache/traceroute/`. Env override `TRACEROUTE_HISTORY_DB`
  (`off` disables). Bound methods: `SaveHistory`, `ListHistory`, `LoadHistory`,
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
- After adding or renaming a bound Go method, run `make bindings` or the
  frontend imports will not compile.

## Testing

- Go tests live beside their packages; use table-driven style.
- `tracerouter` tests use a fake shell binary via `Runner.Binary`.
- `dnscheck` tests use a fake `Resolver` — no real network.
- `geolocator` tests use fake lookups/stores; real-DB tests skip when absent.
- `history` tests use a temp-file SQLite store; no network.
- Keep tests deterministic and offline.

## Security

- Never interpolate user input into a shell string. Targets are validated by
  `tracerouter.validateTarget` and passed to `exec` as an argument array.

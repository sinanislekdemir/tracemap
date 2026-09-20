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

## Versioning

Releases are tagged `vMAJOR.MINOR.PATCH`; pushing a tag triggers the release
workflow that packs the `.deb`/`.rpm`/`.tar.gz`.

- **Always increase the PATCH version first** (e.g. `v0.2.0` → `v0.2.1`).
- Bump the MINOR version only when the PATCH would exceed 9: after `v0.2.9` the
  next release is `v0.3.0`.
- Never skip ahead to a new minor while the current minor still has patch room,
  unless the user explicitly specifies the exact version to tag.

> Note: `v0.3.0` was tagged before this rule existed and should have been
> `v0.2.1`. It stays as-is (the release already ran); the next release is
> `v0.3.1`.

## Layout

```
main.go                     Wails entry; embeds frontend/dist; window options
app.go                      App struct, bound methods (Trace/Scan/ScanPorts/Net*/AnalyzeDomain/ExportDomainReport/Cancel/History/PickWordlist), events
internal/tracerouter/       spawn system traceroute/tracert, parse output
internal/geolocator/        IP -> geo (remote-first, SQLite cache, mmdb fallback)
internal/dnscheck/          A/AAAA/CNAME/MX/NS lookup -> trace targets
internal/domaincheck/       domain security report (RDAP/WHOIS, DNS, email auth, web/TLS)
internal/subdomains/        local subdomain discovery (brute force, PTR, SPF/SRV)
internal/webcrawl/          browser-UA HTTP crawl (frontpage + 1 level, robots, sitemap)
internal/portscan/          TCP connect / UDP port scan + banner/HTTP/TLS probing
internal/origin/            keyless origin discovery behind CDNs/proxies ("unmask")
internal/netcat/            interactive TCP sessions ("nc") for floating windows
internal/history/           saved traces/scans (SQLite snapshot store)
internal/appdata/           shared SQLite database path (tracemap.db)
internal/netutil/           shared host normalization/resolution/IP/dedup helpers
internal/httputil/          shared browser User-Agent
internal/sqliteutil/        shared SQLite open/pragmas/schema helper
internal/ratelimit/         shared context-aware rate limiter
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
  dialog (`ScanOptions`) chooses which techniques run; `ScanOptions.WordlistPath`
  points brute force at a user-supplied newline-delimited file via
  `subdomains.LoadWordlist` (leftmost label kept, bounded to 100k entries), and
  `App.PickWordlist` opens a native file chooser for it. `Discover` reports
  per-phase progress through `Options.OnProgress` (phase `subdomains` for brute
  force, `ptr` for reverse DNS, `sweep` for the `/24` sweep, each with
  done/total/found) and verbose steps through `Options.OnLog`. `App.Scan`
  forwards these as `scan:progress` and `scan:subdomainLog`, and
  `App.TraceTargets` traces a reviewed selection.
- **Web crawl** (`internal/webcrawl`): pure-Go (`net/http` + `x/net/html`, no
  external binary). `Crawl` fetches the frontpage and one level of same-site
  links with a browser `User-Agent`, follows up to 10 HTTP redirects (including
  a redirect that lands on another host, which then defines the same-site root),
  falls back to the `www.` host when the apex candidates fail (never for an IP
  literal), parses `robots.txt` (sitemap directives and Allow/Disallow paths —
  Disallow is ignored, this is a recon tool) and `sitemap.xml` (urlset +
  sitemapindex, gzip-aware, bounded depth), and extracts every in-domain
  hostname. Bodies are
  capped (`MaxBodyBytes`) and flagged truncated. When `ScanOptions.Crawl` is set,
  `App.Scan` runs it alongside DNS discovery, streams `scan:crawlPage` per page,
  `scan:crawlLog` for each fetch attempt/outcome (so the UI shows what it tried)
  and `scan:crawl` with the final `Result`, and merges crawl-discovered hostnames
  into the subdomain list as `source:"crawl"` (persisted via `subdomains.Store`,
  so AutoTrace and the review UI treat them like DNS hits).
- **Port scanning** (`internal/portscan`): pure-Go, no nmap. `App.ScanPorts`
  expands a preset (`top20`/`top100`/`top1000`) or a `ParsePorts` range into a
  port list, then `Scanner.Scan` probes with bounded concurrency, randomised
  port order and jitter. TCP uses a connect scan; UDP sends a protocol-specific
  datagram and reports only replies (best-effort). Optional `Probe` identifies
  the service by banner grab, HTTP `GET`/`Server` header, or TLS handshake
  (cert CN/SAN, issuer, ALPN) on TCP, and by reply shape/banner on UDP
  (DNS/mDNS/NTP labels plus printable banners); on unknown ports TLS is tried
  before HTTP because an HTTP server answers a TLS ClientHello with a misleading
  plaintext `400`.
  Events: `portscan:open`, `portscan:progress`, `portscan:done`,
  `portscan:error`; results are not persisted. `ScanPorts` owns a dedicated
  canceler (`portOps`), so it neither stops nor is stopped by traces/scans;
  `CancelPortScan` stops it. A request may carry multiple `Targets`
  (`PortScanTarget`); each is
  scanned with bounded host concurrency (`portScanHostConcurrency`), `portscan:open`
  carries the owning host/label in a `PortOpenEvent`, and the progress/done
  events report the target index/count. `App.ExportPortScanReport` writes the
  scan context plus the collected open ports as a verbose human-readable text
  report via the native save dialog (`formatPortScanReport`, `.txt`); the
  frontend assembles a `PortScanReport` (scan options, resolved targets, timing,
  `[]PortScanRow`) for it.
- **Domain analysis** (`internal/domaincheck`): builds a security/reliability
  report for a domain. Registration comes from RDAP via the IANA bootstrap
  (`data.iana.org/rdap/dns.json`, cached in memory), falling back to classic
  WHOIS on port 43 (ask `whois.iana.org` for the registry `refer:`). DNS checks
  cover TXT/SPF/DMARC/common DKIM selectors/MTA-STS/TLS-RPT via `net.Resolver`,
  plus CAA/DNSKEY/DS through raw `dnsmessage` queries (net.Resolver has no such
  methods). Web checks capture the HTTP→HTTPS redirect, TLS certificate and
  security headers via `httptrace`. `Analyzer.Analyze` runs each phase
  best-effort and returns a `Report` with a pass/warn/fail checklist, a weighted
  score and a letter grade; `domaincheck.FormatReport` renders the export text.
  Bound methods: `AnalyzeDomain` (streams `domain:progress`, own cancellation
  context independent of `App.begin()`) and `ExportDomainReport` (native save
  dialog). The frontend `DomainAnalysisModal` shows the checklist and details and
  offers Export.
- **Interactive TCP sessions** (`internal/netcat`): line-oriented netcat in a
  floating terminal window. `App.NetConnect` opens a `netcat.Session` (optional
  TLS) and a reader goroutine streams raw bytes as `net:data` events (Go
  `[]byte` → base64); `NetSend`/`NetClose` drive it, and `net:closed` reports
  the reason. Sessions live in their own `Manager` registry, independent of the
  `App.begin()` cancel model, and are all closed on shutdown. The frontend
  (`NetcatPanel`) decodes base64, escapes control characters and caps scrollback;
  closing its window unmounts the panel and closes the session. TCP only; no UDP,
  ANSI terminal emulation, listen mode or file transfer.
- **Origin discovery** (`internal/origin`, "Unmask target"): keyless, all-local
  hunt for the true origin behind a CDN/reverse proxy. `App.UnmaskTarget`
  (own cancellation context, like `AnalyzeDomain`) reuses the last scan's
  subdomains (  `subdomains.Store.Load`) plus the apex, MX hosts, SPF `ip4:`/`ip6:`
  literals and baseline certificate SANs to build candidates, then connects
  directly to each candidate (SNI/Host pinned to the domain) and compares its
  TLS cert SHA-256, favicon and body against the proxied baseline. Content is
  the decisive signal (a proxy passes body/favicon through unchanged) while the
  baseline certificate is the edge's. An address is confirmed only when it
  serves the target's content directly, is not a current DNS answer for the
  domain, and shows no intermediary header (`via`, `x-cache`, `age`,
  `x-served-by`, `x-cdn`, `cdn-*` and stable CDN marker header names such as
  `cf-ray`/`x-amz-cf-id`); a shared-edge SNI probe is supporting evidence.
  Verdicts: confirmed/likely/proxy/dead. The intermediary marker set is
  configurable (`internal/origin/rules.go`): `App.UnmaskRulesPath` reports the
  user's `unmask-rules.json` location, `App.CreateUnmaskRules` copies the
  embedded defaults there for editing (under `appdata.ConfigDir()`), and
  `App.UnmaskTarget(domain, customRules)` loads it when requested. Events:
  `origin:progress` (phases) and `origin:log` (verbose per-step detail); the
  frontend renders the log in an inline LIVE LOG pane inside the modal and also
  mirrors it to the `origin` log channel. `App.ExportOriginReport` writes a
  text report. The frontend `OriginModal` shows the baseline and candidates,
  offers default/custom rules, and drops a building marker on the map for
  confirmed/likely origins. NSEC/AXFR zone enumeration is a documented phase-3
  TODO in `internal/origin/zone.go`.

  literals and baseline certificate SANs to build candidates, then connects
  directly to each candidate (SNI/Host pinned to the domain) and compares its
  TLS cert SHA-256, favicon and body against the proxied baseline. Content is
  the decisive signal (a proxy passes body/favicon through unchanged) while the
  baseline certificate is the edge's. An address is confirmed only when it
  serves the target's content directly, is not a current DNS answer for the
  domain, and shows no intermediary header (`via`, `x-cache`, `age`,
  `x-served-by`, `x-cdn`, `cdn-*` and stable CDN marker header names such as
  `cf-ray`/`x-amz-cf-id`); a shared-edge SNI probe is supporting evidence.
  Verdicts: confirmed/likely/proxy/dead. The intermediary marker set is
  configurable (`internal/origin/rules.go`): `App.UnmaskRulesPath` reports the
  user's `unmask-rules.json` location, `App.CreateUnmaskRules` copies the
  embedded defaults there for editing (under `appdata.ConfigDir()`), and
  `App.UnmaskTarget(domain, customRules)` loads it when requested. Events:
  `origin:progress` (phases) and `origin:log` (verbose per-step detail); the
  frontend renders the log in an inline LIVE LOG pane inside the modal and also
  mirrors it to the `origin` log channel. `App.ExportOriginReport` writes a
  text report. The frontend `OriginModal` shows the baseline and candidates,
  offers default/custom rules, and drops a building marker on the map for
  confirmed/likely origins. NSEC/AXFR zone enumeration is a documented phase-3
  TODO in `internal/origin/zone.go`.
- **History** (`internal/history`): explicit snapshots of completed traces/scans
  in the shared `tracemap.db` (JSON blob per entry + denormalized counts).
  Bound methods: `SaveHistory`, `ListHistory`, `LoadHistory`,
  `DeleteHistory`, `ClearHistory`. The frontend builds the snapshot (it holds the
  async geo results); nothing is saved automatically.
- **GeoIP cache viewer**: `internal/geolocator` exposes the persistent
  `geo_cache` contents through `Resolver.CacheInfo`/`CacheEntries`/
  `DeleteCacheEntry`/`ClearCache` (deleting/clearing also evicts the in-memory
  copy so the next lookup refreshes). Bound methods: `GeoCacheInfo`,
  `ListGeoCache`, `DeleteGeoCacheEntry`, `ClearGeoCache`. The frontend
  `GeoCacheModal` (Tools ▾ → **GeoIP cache**) lists cached replies newest first
  with a filter, per-entry delete and clear-all, and reports whether persistence
  is disabled (`TRACEROUTE_DB` unset/off).
- **Shared-hop correlation** is computed in the frontend (`App.tsx`): IPs present
  in 2+ traces become `sharedHops`, highlighted on the map and in the hop list.

## Frontend conventions

- **No page scrolling.** The app is a fixed `100vh` grid (app bar → toolbar →
  sidebar/splitter/map → status bar). Only panes scroll internally.
- **Floating terminal windows** replace the old bottom dock. `useFloatingWindows`
  owns position/size/z-order; `FloatingWindow` is the draggable/resizable shell
  and `TerminalWindow` renders a channel's log lines (`ConsoleBody`). Each scan
  step opens its own window up front (`handleScanConfirm` opens the enabled
  `dns`/`subdomains`/`crawl`/`trace` windows before the backend events arrive, so
  slow discovery does not hide the pending steps), and netcat sessions each get
  a window. Log lines are stored per channel in
  `App.tsx` (`logChannels`), capped per channel. Scan windows are closed at the
  start of a new operation; console/netcat windows persist.
- **Tool dialogs are floating windows, not blocking modals.** The shared `Modal`
  shell (used by `ScanModal`, `PortScanModal`, `DomainAnalysisModal`,
  `OriginModal`, `HistoryModal`) renders with `modal--float`: no backdrop,
  `position: fixed`, draggable via its header and resizable via the bottom-right
  `.fw-resize` handle. It portals into the `#window-layer` and draws its
  z-order from `zorder.ts`, the same counter `useFloatingWindows` uses, so
  focusing a dialog or a terminal window raises it above the other. The map and
  terminal windows stay visible and interactive behind it. `PortScanModal` is
  the port scanner's terminal (inline LIVE LOG); it no longer opens a separate
  floating `ports` channel window. `MissingToolModal` stays a blocking alert.
- **react-leaflet gotcha:** `className` must be a **top-level prop** on
  `CircleMarker`/`Polyline`. Putting it in `pathOptions` routes it through
  `setStyle()`, which silently drops it. Colours go in `pathOptions`; animations
  go in `className` + CSS.
- **The basemap is fully offline** (no tile server, so it works on Windows and
  without network). Country borders come from Natural Earth 1:110m via
  `world-atlas` + `topojson-client` in `src/world.ts`, cut at the antimeridian
  by `src/antimeridian.ts` (Leaflet would otherwise draw Fiji/Russia as a band
  across the map); major cities come from `src/assets/cities.json`. City names
  only render at `LABEL_ZOOM`+ to avoid clutter.
- **Trace colours** come from `src/colors.ts`, assigned by target index.
- **History view**: `HistoryModal` lists saved entries; loading selection
  replaces the main map's traces with fresh contiguous ids/colours and sets
  `viewMode='history'` (exited by running a new trace or the app-bar EXIT).
- `buildDisplayHops()` (`src/traces.ts`) appends/marks the resolved target IP as
  the final list entry; `isLocated()` treats `(0, 0)` as "no coordinates".
- **Tools dropdown**: `Trace` and `Scan` are top-level toolbar buttons; the
  **Tools ▾** button opens a `ContextMenu`-based dropdown (anchored to the
  button) holding **Domain analysis**, **Unmask target**, **Port scan**,
  **Netcat** and **Console**.
- **Port scan entry points**: the toolbar **Ports** item opens `PortScanModal`
  for the current target. The right-click context menu (`ContextMenu.tsx`, a
  generic cursor menu raised by `HopList`, `TraceList` and the map markers)
  offers **Find open ports** for a specific IP. When more than one resolved scan
  target exists, the modal offers a **TARGETS** scope toggle — *This host* or
  *All targets (N)* — and an **Export report** footer button (calls
  `ExportPortScanReport`) that writes a verbose human-readable `.txt` report
  (scan context + per-target open ports). The
  modal goes options → live
  results, owns its own `portscan:*` subscriptions, and streams open ports into a
  structured table (grouped per host, with a filter and a port/service sort)
  while the raw event stream stays in a collapsible **ACTIVITY** pane
  (`ConsoleBody`, capped at 2000 lines). It cancels through `CancelPortScan`
  (independent of traces). Do not add a `window` `contextmenu` listener to close
  the menu — it can fire for the same event that opened it;
  `pointerdown`/`blur`/`Escape` suffice.
- **Domain analysis**: `DomainAnalysisModal` runs `AnalyzeDomain`, listens to
  `domain:progress`, and renders the checklist/details; **Export** calls
  `ExportDomainReport`. It uses its own cancellation (independent of traces).
- **Unmask target**: `OriginModal` runs `UnmaskTarget`, listens to
  `origin:progress`/`origin:log`, and renders the baseline plus candidate
  verdicts; the verbose log shows in an inline LIVE LOG pane (a fixed-height
  `ConsoleBody`, ~10 lines) inside the modal and is also mirrored to the
  `origin` channel. Confirmed/likely origins are passed up to `App.tsx` and
  drawn on the map as 🏢 markers (`origin-marker` divIcon). Markers clear when a
  new trace/scan starts. The Tools item is disabled until a scan completes
  (`scanCompleted`), hinting "scanning must complete to use this tool".
- After adding or renaming a bound Go method, run `make bindings` or the
  frontend imports will not compile.
- **Crash reporting**: `ErrorBoundary` (root, in `main.tsx`) renders
  `CrashScreen` — the error, its `stack`, the React `componentStack` and the
  environment, with a Copy button. `GlobalErrorBridge` (inside the boundary)
  turns uncaught `window` errors and unhandled promise rejections into render
  errors so they hit the same screen instead of vanishing into the webview
  console.

## Testing

- Go tests live beside their packages; use table-driven style.
- `tracerouter` tests use a fake shell binary via `Runner.Binary`.
- `dnscheck` tests use a fake `Resolver` — no real network.
- `domaincheck` tests use an `httptest` RDAP/web server, a fake resolver/raw
  queryer and a scripted WHOIS dialer; no external network.
- `geolocator` tests use fake lookups/stores; real-DB tests skip when absent.
- `history` tests use a temp-file SQLite store; no network.
- `subdomains` tests use a fake resolver and a temp SQLite cache; no network.
- `origin` tests use a fake resolver, an `httptest` TLS server and an injected
  dialer; no external network.
- `webcrawl` tests serve fixtures from an `httptest.Server` and dial it with a
  custom transport (plus a fake resolver); no external network.
- `portscan` tests scan localhost listeners and `httptest` HTTP/TLS servers; no
  external network. `Scanner.DialContext`/`ResolveIP` can be faked.
- Keep tests deterministic and offline.

## Security

- Never interpolate user input into a shell string. Targets are validated by
  `tracerouter.validateTarget` and passed to `exec` as an argument array.
- Port scanning dials the host from the Go standard library only (no shell); it
  reports only open ports and never sends credentials.

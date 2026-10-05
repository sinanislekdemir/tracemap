# AGENTS.md

Traceroute Map — a **native desktop app** (Go backend + Qt6 Widgets UI via
`miqt`) that runs traceroutes from the local machine and draws them on an
offline vector map. There is no web engine, tile server or Node build.

## Commands

Everything goes through the `Makefile`. The map is drawn by our own QPainter
code, so the only build dependencies are Go, a C++ compiler and the Qt6
development packages.

```sh
make dev          # run the app directly from source
make build        # release binary -> build/bin/traceroute
make run          # build then launch
make check        # go vet + go test + go build  (run before finishing)
make test         # Go tests only
make vet          # go vet only
make sysdeps      # verify Qt6 build/runtime dependencies
make clean        # remove build/bin
```

System packages (Fedora): `qt6-qtbase-devel gcc-c++`.
System packages (Debian/Ubuntu): `qt6-base-dev g++`.
Qt Go bindings: `github.com/mappu/miqt` (Qt6 package `.../qt6`).

Always run `make check` after changes. Never commit unless asked.

## Versioning

Releases are tagged `vMAJOR.MINOR.PATCH`; pushing a tag triggers the release
workflow that packs the `.deb`/`.rpm`/`.tar.gz` (Linux), the macOS `.app` zip and
the Windows zip.

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
main.go                     Qt entry: LockOSThread, QApplication, load world, run UI
app.go                      App struct + backend methods (Trace/Scan/ScanPorts/Net*/AnalyzeDomain/ExportDomainReport/Cancel/History/PickWordlist), event DTOs
cancel.go                   shared cancellable-operation primitive
emit.go                     EventSink + Dialogs interfaces (toolkit-agnostic)
ui_app.go                   uiApp controller: main window, toolbar, sidebar, status bar, event dispatch, map model
ui_model.go                 UI state types, trace colours, correlation, route/bezier building
ui_logwindow.go             floating per-channel log windows (console/dns/subdomains/crawl/trace/ports/origin)
ui_dialogs.go               native Qt Dialogs (QFileDialog/QMessageBox) for the backend
ui_scan.go                  advanced-scan options window
ui_port.go                  port-scan window (options + results table + activity)
ui_tools.go                 domain / unmask / endpoint / GeoIP cache / country-blocks windows
ui_netcat.go                floating interactive TCP sessions
ui_helpers.go               CIDR target parsing (mirrors hostscan.ParseCIDR)
internal/mapdata/           embedded Natural Earth GeoJSON + cities, TopoJSON decode, antimeridian split, Web Mercator
internal/mapview/           custom QPainter map widget: layers, pan/zoom, hit-testing
internal/tracerouter/       spawn system traceroute/tracert, parse output
internal/geolocator/        IP -> geo (remote-first, SQLite cache, mmdb fallback)
internal/dnscheck/          A/AAAA/CNAME/MX/NS lookup -> trace targets
internal/domaincheck/       domain security report (RDAP/WHOIS, DNS, email auth, web/TLS)
internal/subdomains/        local subdomain discovery (brute force, PTR, SPF/SRV)
internal/webcrawl/          browser-UA HTTP crawl (frontpage + 1 level, robots, sitemap)
internal/hostscan/          IPv4 CIDR enumeration + live-host discovery (TCP connect)
internal/portscan/          TCP connect / UDP port scan + banner/HTTP/TLS probing + worker pool
internal/origin/            keyless origin discovery behind CDNs/proxies ("unmask")
internal/netcat/            interactive TCP sessions ("nc") for floating windows
internal/history/           saved traces/scans (SQLite snapshot store)
internal/appdata/           shared SQLite database path (tracemap.db)
internal/netutil/           shared host normalization/resolution/IP/dedup helpers
internal/httputil/          shared browser User-Agent
internal/sqliteutil/        shared SQLite open/pragmas/schema helper
internal/ratelimit/         shared context-aware rate limiter
build/                      appicon.png + Linux desktop file
.github/workflows/          CI (make check) + tag-triggered release builds
                            (release.yml pins ubuntu-24.04/macos-14 and guards the
                            Qt6 baseline — see QT_BASELINE and nfpm.yaml; Windows
                            is cross-compiled from Linux via the cached image in
                            win/ — no Windows runner)
win/                        MinGW-w64 + static Qt6 cross-compile image for the
                            Windows build (Dockerfile, pkgconfig/, build.sh)
PLAN.md                     design/architecture document
```

## Architecture notes

- **Backend is in-process.** There is no HTTP server or WebSocket. The Qt UI
  calls the Go methods directly and installs `App.SetEmitter` to receive typed
  events; backend goroutines marshal onto the Qt GUI thread with
  `mainthread.Start`. Native file/message dialogs are injected through the
  `Dialogs` interface so the backend stays toolkit-agnostic.
- **Every trace event carries a `target` id.** `0` is the single-trace view;
  `Scan` assigns `1..N` to the addresses it traces, so the UI can group and
  colour concurrent traces.
- **Advanced scan** (`App.Scan`): resolve the domain's records (including SOA
  via a raw query — `net.Resolver` has no SOA method), expand them by following
  `NS` hostnames and the SOA primary nameserver recursively (`dnscheck.Expand`,
  bounded by `MaxNSDepth`/`maxNSHosts`), emit `scan:records` then `scan:targets`,
  trace each address with bounded concurrency (`scanConcurrency`), then
  `scan:done`. IPv6 targets are dropped when the host has no global IPv6 address
  (`filterUnroutable`). The DNS work is parallel: `dnscheck.Lookup` runs its
  A/AAAA, CNAME, MX and NS queries concurrently, `Expand` resolves each
  nameserver level concurrently (`expandConcurrency`) and `AllTargets` resolves
  the MX/NS/SOA hosts concurrently (`targetConcurrency`); `App.Scan` also starts
  `AllTargets` in a goroutine so it overlaps subdomain discovery and the crawl.
  Results are merged in a stable order, so target ids and record order do not
  depend on which lookup finishes first.
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
  SPF/DMARC TXT and SRV records. Bounded concurrency + rate limiter; the ~30
  SRV lookups fan out concurrently (`serviceConcurrency`) and their targets are
  resolved in service order. Brute force and the services pass run concurrently
  (reverse DNS runs after, since it consumes their IPs), and the collector keeps
  the most specific source for a name (`sourceRank`: brute > spf > dmarc > srv >
  ptr) so the result does not depend on phase order. Lookup concurrency and rate
  are configurable through `ScanOptions.SubdomainConcurrency`/`SubdomainRate`
  (the scan dialog exposes them as "Parallel / lookups · lookups/s"). Results are
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
  hostname. Sitemaps are fetched a BFS level at a time with each level's fetches
  run concurrently (`Options.Concurrency`), and the parsed sitemaps are appended
  in level order so the result is deterministic. Bodies are
  capped (`MaxBodyBytes`) and flagged truncated. When `ScanOptions.Crawl` is set,
  `App.Scan` runs it alongside DNS discovery, streams `scan:crawlPage` per page,
  `scan:crawlLog` for each fetch attempt/outcome (so the UI shows what it tried)
  and `scan:crawl` with the final `Result`, and merges crawl-discovered hostnames
  into the subdomain list as `source:"crawl"` (persisted via `subdomains.Store`,
  so AutoTrace and the review UI treat them like DNS hits).
- **Port scanning** (`internal/portscan`): pure-Go, no nmap. `App.ScanPorts`
  expands a preset (`top20`/`top100`/`top1000`) or a `ParsePorts` range into a
  port list, then `Scanner.Scan` probes with bounded concurrency, randomised
  port order and jitter. Probes run on a reusable, fixed-size worker pool
  (`internal/portscan/pool.go`): `Scanner.Scan` uses a short-lived pool sized to
  the requested concurrency, while `App.ScanPorts` creates one `portscan.Pool`
  for the whole operation (`portProbeBudget` = `portScanHostConcurrency` ×
  per-host concurrency) and shares it across every host, so a CIDR block probe
  never spawns a goroutine per port. TCP uses a connect scan; UDP sends a protocol-specific
  datagram and reports only replies (best-effort). Optional `Probe` identifies
  the service by banner grab, HTTP `GET`/`Server` header, or TLS handshake
  (cert CN/SAN, issuer, ALPN) on TCP, and by reply shape/banner on UDP
  (DNS/mDNS/NTP labels plus printable banners); on unknown ports TLS is tried
  before HTTP because an HTTP server answers a TLS ClientHello with a misleading
  plaintext `400`. On the FTP port (21, or any port whose greeting looks like an
  FTP `220`) the probe also attempts an anonymous login (`USER anonymous` /
  `PASS`) and records the verdict in `Result.FTPAnonymous`; the port-scan report
  prints `anonymous FTP: ANONYMOUS LOGIN ALLOWED` / `authentication required`.
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
- **IPv4 CIDR block targets** (`internal/hostscan`): when the toolbar target box
  holds an IPv4 CIDR (detected by `ui_helpers.go`'s `parseBlockTarget`, which
  mirrors `hostscan.ParseCIDR` for the block part and `portscan.ParsePorts` for
  the port part), Trace and Ports switch to block mode. The target may carry an
  optional `:ports` suffix (`10.0.0.0/24:22,80,443-445`, comma-separated ports
  and ranges); the parser strips it, the toolbar shows a `PORTS · …` badge, and
  the parsed spec is passed as `TraceBlockRequest.PortRange` /
  `PortScanRequest.PortRange`. Without it, blocks fall back to the top-100 list.
  `App.TraceBlock` (`TraceBlockRequest{cidr,portRange,maxHops}`) enumerates the
  usable addresses (`hostscan.Each`, streaming — network/broadcast excluded up
  to /30), discovers live hosts by TCP-connecting to the selected ports
  concurrently (`hostscan.Discover`, bounded hosts×ports, first open port
  short-circuits the rest), then traces each live address through the normal
  `traceScan` pipeline (`scan:targets`/`scan:done`). Discovery streams
  `scan:progress` phase `discover` and verbose `block:log` events; it uses the
  shared `App.begin()` canceler, so Cancel stops it. No hard block-size cap:
  blocks over 65536 addresses log a warning. Scan/Ports on a CIDR opens
  `PortScanDialog` in block mode (it sets `PortScanRequest.cidr`): the backend's
  `scanPortBlock` enumerates the block internally and scans all hosts with
  `portScanHostConcurrency`, reporting host-level (not per-port) progress so the
  event stream stays bounded.
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
  The registration, DNS and web phases run concurrently, and `dnsReport` fans
  out its independent groups (apex records, DMARC, the ~15 DKIM selectors —
  bounded by `dnsProbeConcurrency` — MTA-STS/TLS-RPT and the raw CAA/DNSKEY/DS
  queries), folding the results back together in a stable order.
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
  TLS cert SHA-256, favicon and body against the proxied baseline. Candidates
  are verified concurrently (`Options.Concurrency`), and each candidate's own
  ports are probed concurrently (`portProbeConcurrency`); the strongest match is
  then selected in configured port order. Content is
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
  TLS cert SHA-256, favicon and body against the proxied baseline. Candidates
  are verified concurrently (`Options.Concurrency`), and each candidate's own
  ports are probed concurrently (`portProbeConcurrency`); the strongest match is
  then selected in configured port order. Content is
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
- **Country IP blocks** (`internal/ipblocks`): browses the local GeoLite2
  Country/City database by country. `Open` prefers `GeoLite2-Country.mmdb`, then
  `GeoLite2-City.mmdb` (`TRACEROUTE_GEOIP_COUNTRY_DB`/`TRACEROUTE_GEOIP_CITY_DB`
  override, then `TRACEROUTE_GEOIP_DIR`, then the conventional dirs). A full
  `Reader.Networks` walk (~3.6M networks, ~2.5s) yields the per-country summary
  (`Countries`, cached once) and a country's prefixes (`Blocks`, one country
  cached at a time; `ClearCache` frees it). `Paginate` applies the family and
  CIDR-substring filters and an address-space sum; a negative `Limit` keeps
  every match for exports. Bound methods: `IPBlocksInfo`, `ListCountryBlocks`,
  `QueryCountryBlocks`, `ReleaseCountryBlocks`, `ExportCountryBlocks` (plain
  CIDR lines + summary header). The walk streams `ipblocks:progress`. The
  frontend `IPBlocksModal` (Tools ▾ → **Country IP blocks**) lists countries
  with block/address counts, then shows a paged/filtered block list (first 2000
  lines) and offers **Export blocks**; `ReleaseCountryBlocks` is called on
  close. Because a country like the US has ~1.45M blocks, the modal never
  renders the full list on screen.
- **Shared-hop correlation** is computed in the UI (`ui_model.go`): IPs present
  in 2+ traces become `sharedHops`, highlighted on the map and in the hop list.

## UI conventions (Qt6 / miqt)

- **The map is hand-painted and offline.** `internal/mapview` draws the embedded
  Natural Earth geometry (TopoJSON decoded and cut at the antimeridian by
  `internal/mapdata`) and the trace overlay with `QPainter` in a custom
  `QWidget`. It owns pan/zoom (wheel = zoom about the cursor, drag = pan) and
  hit-testing; markers carry the trace/hop metadata. No tile server, web engine
  or network call is involved. City labels only render above a zoom threshold.
- **Web-Mercator, our own transform.** `mapdata.Mercator` returns normalized
  [0,1] coordinates; the widget scales by `TileSize * 2^zoom`. Land/country
  `QPainterPath`s are built once at startup and reused across zoom and theme.
- **One main window.** Toolbar row (target box + PORTS badge, Trace/Scan/Ports/
  Cancel, Tools menu, Correlate, theme toggle) -> `QSplitter` (sidebar tabs:
  Hops / Traces / Subdomains / Correlation | map) -> `QStatusBar`. Panes scroll
  internally; the window itself does not.
- **Floating windows are native decorated tool windows.** Each console/log
  channel (`dns`, `subdomains`, `crawl`, `trace`, `ports`, `origin`, `console`)
  is a `QWidget`/`QDialog` with a `QPlainTextEdit`, created lazily via
  `ensureChannel`. Netcat sessions and every tool dialog (scan, port, domain,
  unmask, endpoint, GeoIP cache, country blocks) are their own windows.
- **Typed events, no JSON.** `app.go` emits Go structs through `EventSink`;
  `ui_app.go`'s `handle` type-switches on them. All UI mutation runs on the Qt
  GUI thread via `mainthread.Start`.
- **Trace colours** come from `ui_model.go` (`traceColors`, assigned by target
  index); `correlationColor` heats up revisited hops.
- **Shared-hop correlation** is computed in `ui_model.go` (`correlate`): IPs in
  2+ traces become `sharedHops`, highlighted on the map and in the sidebar.
- `buildDisplayHops` appends/marks the resolved target IP as the final entry;
  `isLocated` treats `(0, 0)` as "no coordinates".
- **CIDR block targets** are detected by `parseBlockTarget` (`ui_helpers.go`),
  which mirrors `hostscan.ParseCIDR` / `portscan.ParsePorts`.

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
  external network. `Scanner.DialContext`/`ResolveIP` can be faked. The worker
  pool is tested with a blocking fake dialer: `pool_test.go` asserts the
  concurrency cap (also across concurrent `Pool.Scan` calls), reuse across
  sequential scans, and the closed/cancelled paths.
- Keep tests deterministic and offline.

## Security

- Never interpolate user input into a shell string. Targets are validated by
  `tracerouter.validateTarget` and passed to `exec` as an argument array.
- Port scanning dials the host from the Go standard library only (no shell); it
  reports only open ports and never sends credentials.

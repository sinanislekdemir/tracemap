# Traceroute Map — Project Plan

A desktop app that visualizes network traceroutes on a world map. The user enters
a target host, the app runs a traceroute **from the local machine**, resolves the
geographic location of each hop, and draws the path as an animated polyline on an
OpenStreetMap map.

## 1. Goal & Scope

**In scope (v1)**
- Enter a hostname/IP and run a traceroute from the local machine.
- Geo-locate every responsive hop (IP → lat/lon, city, country, ASN/ISP).
- Render the ordered path on an interactive map with per-hop markers and labels.
- Stream hops into the UI as they arrive, with a per-hop RTT/detail list.
- **Advanced scan**: resolve a domain's A/AAAA/CNAME/MX/NS/SOA records and trace
  every address found, drawing all paths on one map with a colour legend.
  `NS` records and the SOA primary nameserver are expanded recursively (bounded)
  so nameserver hostnames and their addresses become trace targets too.
- **Subdomain discovery** (local DNS only): a scan-options dialog controls
  brute force (embedded 1000+-name wordlist, wildcard-filtered), reverse DNS
  (PTR, optional `/24` sweep), and SPF/DMARC/SRV extraction. Results are cached
  and can be reviewed and traced selectively.
- **Web crawl**: an optional scan phase fetches the frontpage and one level of
  same-site links with a browser `User-Agent`, parses `robots.txt` and
  `sitemap.xml`, and folds every in-domain hostname it sees into the subdomain
  list (`source:"crawl"`). Pure Go; no `curl`/`wget`.
- **History**: explicitly save completed traces/scans to a local database, then
  load any selection back onto the map to compare paths; hops shared by two or
  more traces are highlighted.
- **Port scanning**: right-click a target or hop to scan it for open ports
  (pure-Go TCP connect / best-effort UDP, no nmap) over common-port presets or a
  custom range, with randomised order and jitter, optionally identifying the
  service via banner/HTTP/TLS probing.
- Cancel a running trace or scan.

**Out of scope (v1)**
- Running traceroute from a remote server or multiple vantage points.
- Automatic (implicit) history capture and trace diffing.

## 2. Key Technical Constraint

Raw ICMP sockets cannot be opened from the webview, and the app is meant to
measure the **user's own** network path. The Go backend therefore runs the system
`traceroute`/`tracert` binary locally and streams parsed hops to the UI. No HTTP
server or WebSocket is involved: the Go backend is linked into the app and
exposed to the frontend through Wails bindings and events.

## 3. Architecture

```
Wails window (React + Leaflet map UI)
   │  Bind: Trace(req), Scan(req), ScanPorts(req), Cancel()
   │  Events: trace:hop, trace:geo, trace:done, trace:error, portscan:open, …
   ▼
Go backend (in-process)
   ├── tracerouter  (spawn system traceroute/tracert, parse output)
   ├── geolocator   (IP → lat/lon, city, country, ASN; cached)
   ├── dnscheck     (A/AAAA/CNAME/MX/NS/SOA lookup → trace targets)
   ├── subdomains   (local discovery: brute force, PTR, SPF/DMARC, SRV)
   ├── webcrawl     (browser-UA HTTP crawl: frontpage + 1 level, robots, sitemap)
   ├── portscan     (TCP connect / UDP scan; banner/HTTP/TLS probing)
   └── history      (saved traces/scans; SQLite snapshot store)
```

### 3.1 Backend (Go)
- **Traceroute execution** (`internal/tracerouter`): discover the first
  available tool — `traceroute`, then `tracepath`, then `mtr` on Unix;
  `tracert` on Windows — on `PATH` or at conventional absolute paths, and build
  tool-specific flags (numeric output for speed and stable parsing). The parser
  auto-detects traceroute/tracert/tracepath/mtr formats and merges tracepath's
  repeated per-probe lines. Max-hops and timeout are configurable (default 30
  hops, 30s budget).
- **Streaming**: `ExecuteStream` invokes a callback per parsed hop line, which
  `App.Trace` forwards to the frontend as a `trace:hop` event.
- **GeoIP resolution** (`internal/geolocator`): resolve each responsive hop IP,
  preferring the public `ipwho.is` API (the source of truth), rate limited to
  2 requests/second. Replies are kept in a persistent SQLite cache
  (`geo_cache` table in `tracemap.db`), so repeated hops are served instantly.
  When the remote service fails, a local **GeoLite2** database
  (`GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb`, auto-detected under
  `/usr/share/GeoIP` and friends) is used instead. Overrides:
  `TRACEROUTE_GEOIP_CITY_DB`, `TRACEROUTE_GEOIP_ASN_DB`, `TRACEROUTE_GEOIP_DIR`.
  Lookups run in background goroutines and emit `trace:geo`, so geo never blocks
  the trace. Private/loopback addresses are reported as unresolved without a
  lookup.
- **Input validation**: strictly validate the target (hostname/IP regex) to
  prevent command injection — args are passed as an array via `os/exec`, never
  interpolated into a shell string.
- **Database** (`internal/appdata`): one `tracemap.db` in the per-user config
  directory (`~/.config/traceroute/` on Linux, `~/Library/Application Support/`
  on macOS, `%AppData%\traceroute\` on Windows) holds the `geo_cache`,
  `history_entry` and `subdomain` tables; `TRACEROUTE_DB` overrides the path,
  `off` disables persistence.
- **History** (`internal/history`): explicit snapshots of completed traces/scans
  in the shared `tracemap.db`. Each entry stores the trace snapshot as JSON
  alongside denormalized trace/hop counts. The frontend supplies the snapshot
  because it owns the asynchronously resolved geo data.
- **Port scanning** (`internal/portscan`): pure-Go, no nmap. `ParsePorts`
  validates single ports and ranges; the `top20`/`top100`/`top1000` presets come
  from an embedded common-port table. `Scanner.Scan` probes with bounded
  concurrency, randomised port order and jitter. TCP is a connect scan; UDP
  sends a protocol-specific datagram and reports only replies (best-effort).
  `Probe` identifies services by banner, HTTP `Server` header, or TLS handshake
  (cert CN/SAN, issuer, ALPN). Results stream as events and are not persisted.
- **Cancellation**: `App.Cancel` cancels the running trace, scan or port scan.

### 3.2 Frontend (React + TypeScript)
- **Map**: Leaflet + OpenStreetMap tiles (no API key, free) via `react-leaflet`.
- **Path rendering**: ordered polyline through hop coordinates; a marker per hop
  with a popup showing hop #, IP, RTT, city and ASN.
- **Detail table**: numbered hop list; unresponsive hops (`*`) shown as gaps;
  geo data fills in as lookups complete.
- **Controls**: target input, "Trace"/"Cancel" buttons, max-hops option,
  loading state, and error display.
- **Handling unknowns**: private hops and GeoIP misses have no coordinates — they
  stay in the list but are omitted from the map.
- **History & comparison**: an "Add to history" action saves the current view;
  a modal lists saved entries and loads a selection back onto the main map with
  fresh colours. Hops appearing in 2+ traces are marked as shared on the map and
  in the hop list so common paths stand out.

## 4. Tech Stack

| Layer       | Choice                                             |
|-------------|----------------------------------------------------|
| Shell       | Wails v2 (native WebKit/WebView2 window)           |
| Backend     | Go (stdlib + Wails runtime)                        |
| Traceroute  | System `traceroute`/`tracert` via `os/exec`        |
| Port scan   | stdlib `net` TCP connect / UDP + `crypto/tls` probing |
| DNS         | stdlib `net.Resolver` + raw SOA query         |
| GeoIP       | Local GeoLite2 (City + ASN `.mmdb`), `ipwho.is` fallback |
| Concurrency | goroutines for parallel hop geo lookups            |
| Frontend    | Vite + React 19 + TypeScript                       |
| Map         | Leaflet + OpenStreetMap                            |
| Packaging   | Single native binary (`wails build`)               |

> On Linux with WebKitGTK 4.1 the build requires the `webkit2_41` tag:
> `wails build -tags webkit2_41`. Runtime dependencies: `webkit2gtk4.1`,
> `gtk3`.

## 5. Backend Interface (Wails)

Bound methods (JS: `wailsjs/go/main/App`):

```ts
Trace(req: { target: string; maxHops: number }): Promise<void>
Scan(req: { domain, maxHops, options: ScanOptions }): Promise<void>
TraceTargets(req: { domain, maxHops, hosts: string[] }): Promise<void>
ScanPorts(req: { host, protocol, preset, portRange, concurrency, timeoutMs, probe }): Promise<void>
Cancel(): Promise<void>
SaveHistory(req: { kind, label, maxHops, traces }): Promise<number>
ListHistory(): Promise<HistorySummary[]>
LoadHistory(ids: number[]): Promise<HistoryEntry[]>
DeleteHistory(id: number): Promise<void>
ClearHistory(): Promise<void>
```

`ScanOptions` selects NS expansion, subdomain techniques (brute force, PTR,
`/24` sweep, SPF/DMARC/SRV) and auto-trace vs. review.

Events emitted to the frontend (`wailsjs/runtime`). Every trace event carries a
`target` id so the UI can group and colour concurrent traces (id `0` is the
single-trace view):

```ts
'trace:hop'       → { target, hop, ip?, rttMs? }
'trace:geo'       → { target, hop, geo: GeoData }
'trace:target'    → { target, ip }       // address the target resolved to
'trace:targetGeo' → { target, geo }      // geolocation of the target address
'trace:done'      → { target, hops }     // one trace finished
'trace:error'     → { target, message }  // target 0 = whole operation failed
'scan:records'    → DNSRecord[]          // A/AAAA/CNAME/MX/NS/SOA answers
'scan:subdomains' → SubdomainResult[]    // discovered subdomains
'scan:progress'   → { phase, done, total, found }
'scan:targets'    → ScanTarget[]         // addresses that will be traced
'scan:done'       → number               // targets completed
'portscan:open'     → PortResult         // one open port (port, protocol, service, product, …)
'portscan:progress' → { host, done, total, open }
'portscan:done'     → { host, scanned, open }
'portscan:error'    → { target: 0, message }
```

The target address is read from the traceroute header and always shown as the
final entry in the hop list and map, even when the trace never reaches it.

## 6. Milestones

1. **M0 — Skeleton**: Wails project, Go backend bound, React frontend, window. ✅
2. **M1 — Traceroute core**: run + parse traceroute; unit-tested parser. ✅
3. **M2 — GeoIP**: resolve hop IPs, cache, stream results. ✅
4. **M3 — Map**: Leaflet map, polyline + markers. ✅
5. **M4 — Streaming**: per-hop events, progress + cancel UI. ✅
6. **M5 — Polish**: validation, errors, responsive UI, icons, packaging. ⏳
7. **M6 — Advanced scan**: DNS record lookup, multi-target tracing, colour
   legend and per-target list. ✅
8. **M7 — History & comparison**: explicit save to SQLite, history modal, replay
   selection on the map, shared-hop highlighting. ✅
9. **M8 — Subdomain discovery**: scan-options modal, embedded wordlist brute
   force with wildcard filtering, PTR/SPF/DMARC/SRV, SQLite cache, review pane
   and selective tracing. ✅
10. **M9 — Port scanning**: right-click context menu on targets/hops/markers,
    options → live-results modal, TCP connect + best-effort UDP scan over
    presets/ranges, banner/HTTP/TLS service identification. ✅
11. **M10 — Unmask target**: keyless origin discovery behind CDNs/proxies.
    Mines the target's own DNS footprint (reused scan subdomains, MX, SPF
    `ip4:`/`ip6:`, cert SANs), connects directly to each candidate with SNI/Host
    pinned to the domain, and compares cert SHA-256, favicon and body against
    the proxied baseline. No vendor ranges or third-party services; generic
    intermediary headers and a shared-edge SNI probe gate the verdict. The
    marker set is loadable from an editable `unmask-rules.json` (defaults
    embedded, `CreateUnmaskRules` materialises it). Verbose progress streams to
    an inline LIVE LOG pane in the modal. Map building markers for
    confirmed/likely origins; the tool is gated on a completed scan. ✅
    (NSEC/AXFR zone enumeration is a phase-3 TODO in
    `internal/origin/zone.go`.)

## 7. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Command injection via target input | Strict validation; arg-array exec; never shell-interpolate |
| GeoIP misses / private IPs | Show hop without coords; mark as "Private network"/unknown |
| GeoIP accuracy (city-level is approximate) | Label as approximate; show ASN/country as primary info |
| Slow geo lookups | Resolve in background goroutines; cache by IP |
| `traceroute` not installed | Surface the exec error in the UI |
| Raw sockets need privileges | Use the system binary; port scan uses unprivileged connect/UDP probes |
| Port scanning an unauthorised host | Warn in the dialog; only report open ports; no credentials sent |

## 8. Future (v2+)

- Trace diffing and saved/shareable traces.
- Automatic history capture and retention limits.
- Latency heatmap along the path; per-hop packet-loss stats.
- ASN/IXP overlay and geographic great-circle path arcs.
- IPv6 support and UDP/TCP/ICMP protocol selection in the UI.
- Database freshness indicator and optional `geoipupdate` integration.

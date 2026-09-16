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
- **Advanced scan**: resolve a domain's A/AAAA/CNAME/MX/NS records and trace
  every address found, drawing all paths on one map with a colour legend.
- **History**: explicitly save completed traces/scans to a local database, then
  load any selection back onto the map to compare paths; hops shared by two or
  more traces are highlighted.
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
   │  Bind: Trace(req), Cancel()
   │  Events: trace:hop, trace:geo, trace:done, trace:error
   ▼
Go backend (in-process)
   ├── tracerouter  (spawn system traceroute/tracert, parse output)
   ├── geolocator   (IP → lat/lon, city, country, ASN; cached)
   ├── dnscheck     (A/AAAA/CNAME/MX/NS lookup → trace targets)
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
  2 requests/second. Replies are kept in a persistent SQLite cache next to the
  binary (`geo-cache.db`), falling back to the user cache directory when that
  directory is not writable, so repeated hops are served instantly. When the
  remote service fails, a local **GeoLite2** database (`GeoLite2-City.mmdb` +
  `GeoLite2-ASN.mmdb`, auto-detected under `/usr/share/GeoIP` and friends) is
  used instead. Overrides: `TRACEROUTE_GEOIP_CACHE` (`off` disables),
  `TRACEROUTE_GEOIP_CITY_DB`, `TRACEROUTE_GEOIP_ASN_DB`,
  `TRACEROUTE_GEOIP_DIR`. Lookups run in background goroutines and emit
  `trace:geo`, so geo never blocks the trace. Private/loopback addresses are
  reported as unresolved without a lookup.
- **Input validation**: strictly validate the target (hostname/IP regex) to
  prevent command injection — args are passed as an array via `os/exec`, never
  interpolated into a shell string.
- **History** (`internal/history`): explicit snapshots of completed traces/scans
  in a SQLite database (`history.db` next to the binary, else the user cache
  directory; `TRACEROUTE_HISTORY_DB`, `off` disables). Each entry stores the
  trace snapshot as JSON alongside denormalized trace/hop counts. The frontend
  supplies the snapshot because it owns the asynchronously resolved geo data.
- **Cancellation**: `App.Cancel` cancels the running trace's context.

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
| DNS         | stdlib `net.Resolver` (A/AAAA/CNAME/MX/NS)         |
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
Scan(req: { domain: string; maxHops: number }): Promise<void>
Cancel(): Promise<void>
SaveHistory(req: { kind, label, maxHops, traces }): Promise<number>
ListHistory(): Promise<HistorySummary[]>
LoadHistory(ids: number[]): Promise<HistoryEntry[]>
DeleteHistory(id: number): Promise<void>
ClearHistory(): Promise<void>
```

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
'scan:records'    → DNSRecord[]          // A/AAAA/CNAME/MX/NS answers
'scan:targets'    → ScanTarget[]         // addresses that will be traced
'scan:done'       → number               // targets completed
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

## 7. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Command injection via target input | Strict validation; arg-array exec; never shell-interpolate |
| GeoIP misses / private IPs | Show hop without coords; mark as "Private network"/unknown |
| GeoIP accuracy (city-level is approximate) | Label as approximate; show ASN/country as primary info |
| Slow geo lookups | Resolve in background goroutines; cache by IP |
| `traceroute` not installed | Surface the exec error in the UI |
| Raw sockets need privileges | Use the system binary; document `CAP_NET_RAW` if raw mode added |

## 8. Future (v2+)

- Trace diffing and saved/shareable traces.
- Automatic history capture and retention limits.
- Latency heatmap along the path; per-hop packet-loss stats.
- ASN/IXP overlay and geographic great-circle path arcs.
- IPv6 support and UDP/TCP/ICMP protocol selection in the UI.
- Database freshness indicator and optional `geoipupdate` integration.

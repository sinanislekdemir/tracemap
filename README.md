# tracemap

[![CI](https://github.com/sinanislekdemir/tracemap/actions/workflows/ci.yml/badge.svg)](https://github.com/sinanislekdemir/tracemap/actions/workflows/ci.yml)

**A desktop traceroute visualizer.** tracemap runs `traceroute`/`tracert` from
your own machine, geolocates every responsive hop, and draws the path on an
interactive world map (rendered fully offline — no tile server). It can resolve
a domain's DNS records and trace every
address it finds, save completed traces to a local database, replay any
selection back onto the map to compare routes and spot shared hops, grade a
domain's security and reliability with a WHOIS/RDAP, DNS, email-auth and TLS
report, and hunt for the true origin address behind a CDN or reverse proxy.

Built with **Qt6 Widgets** (via [`mappu/miqt`](https://github.com/mappu/miqt)) —
a Go backend and a native UI in one binary, with the map drawn directly by our
own QPainter code (no web engine, no tile server).

## Screenshots
I keep changing the UI, therefore I can't put screenshots for every feature.
This shall give you an impresssion:
<img width="1310" height="912" alt="Screenshot_20261006_073744" src="https://github.com/user-attachments/assets/a8f4ef90-b4c9-45bc-ab9b-d0454b514cf8" />
<img width="1293" height="900" alt="Screenshot_20261006_073755" src="https://github.com/user-attachments/assets/e1d31999-a76f-4d38-8844-f31d826d7520" />
<img width="1289" height="892" alt="Screenshot_20261006_073829" src="https://github.com/user-attachments/assets/d960d282-f8e7-4d7f-a043-fcc08faa4405" />

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
  (with wildcard filtering) or a custom newline-delimited wordlist file,
  reverse-resolve (PTR) discovered IPs, sweep `/24` netblocks, and extract hosts
  from SPF/DMARC TXT and SRV records. Results are cached locally and can be
  reviewed and traced selectively. Every phase reports live progress (brute
  force, PTR and the `/24` sweep each show done/total and how many names were
  found) and streams each step into the SUBDOMAINS terminal window, so a slow
  sweep never looks stuck.
- **Web crawl** — optionally crawl the domain's front page and one level of
  same-site links with a browser `User-Agent`, following redirects and falling
  back to the `www.` host when the apex fails (never for an IP literal). It also
  reads `robots.txt` and `sitemap.xml` (including sitemap indexes and gzipped
  sitemaps) and folds every in-domain hostname it finds into the subdomain list.
  Pure Go — no `curl`, `wget` or other external tools.
- **Port scanning** — right-click a target or hop and choose **Find open ports**.
  The pure-Go scanner (no nmap) does a TCP connect scan or best-effort UDP
  probe over common-port presets or a custom range, with randomised port order
  and jitter to reduce the scan signature. Probes run on a fixed-size worker
  pool that is shared across every host in a multi-target or CIDR-block scan,
  so a large block never spawns a goroutine per port. Open ports are optionally identified
  by banner grab, HTTP request and TLS handshake on TCP (server, certificate and
  ALPN), and by reply shape or printable banner on UDP (DNS, mDNS and NTP are
  labelled); an FTP service is also checked for an anonymous login. Open ports
  stream into a results table, and **Export report** writes a verbose text report
  of the scan context and every open port. The window can scan either the current
  host or **All targets** from the last scan, a whole IPv4 CIDR block, with
  adjustable concurrency and per-port timeout.
- **Domain analysis** — the **Tools ▾ → Domain analysis** report grades a domain
  on security and reliability. Registration data comes from RDAP via the IANA
  bootstrap, falling back to classic WHOIS (asking IANA for the registry server).
  It checks domain age and expiry, registry status and nameserver redundancy;
  SPF, DMARC, DKIM (common selectors), MTA-STS and TLS-RPT; DNSSEC and CAA; and
  the HTTPS certificate, HTTP→HTTPS redirect, HSTS and security headers. The
  result is a pass/warn/fail checklist with a weighted score and letter grade,
  plus a detailed breakdown that can be exported to a text report.
- **Unmask target (origin discovery)** — the **Tools ▾ → Unmask target** tool
  hunts for the true origin address behind a CDN or reverse proxy, using only
  local DNS and direct connections (no API keys, no vendor IP ranges). It mines
  the target's own footprint — the last scan's subdomains, `MX` hosts, SPF
  `ip4:`/`ip6:` literals and the certificate SANs — then connects directly to
  each candidate with the SNI/Host pinned to the domain and compares its TLS
  certificate, favicon and response body against the proxied baseline. An
  address is confirmed only when it serves the target's content directly, is not
  a current DNS answer for the domain, and shows no intermediary header; a
  shared-edge SNI probe is supporting evidence. Confirmed and likely origins are
  drawn on the map as 🏢 markers. The intermediary marker set is editable: copy
  the built-in rules to `unmask-rules.json` and the tool can load them. Verbose
  progress streams into a LIVE LOG pane in the dialog.
- **Interactive TCP sessions** — open a netcat-style session to a host and port
  from **Tools ▾ → Netcat** or the port-scan row menu. A line-oriented terminal
  in its own floating window sends what you type and streams the peer's raw
  output back; optional TLS (with an SNI-name override), a connect timeout, a
  **Disconnect** button and a protocol cheatsheet. Closing the window ends the
  session. TCP only.
- **Geolocation** — every responsive hop is resolved to coordinates, city,
  country and ASN/ISP, with a persistent cache so repeat hops are instant. The
  coordinates are shown in the hop list and map popup, with an **Open in
  OpenStreetMap** link that opens the location in your default browser.
- **Offline world map** — the basemap is bundled Natural Earth vector data
  (1:110m country borders plus 243 major cities), so it needs no network and no
  tile server and works on every platform. A TRACES legend overlay keys each
  trace's colour, a scale bar shows the current zoom's ground distance, and a
  HUD reports located/shared totals.
- **Trace visibility & status** — tick the checkbox on a trace in the TARGETS
  list to show or hide it on the map, and right-click a trace or hop for
  **Find open ports** / **Trace this host**. **Motion** (on by default) animates
  a travelling marker along each route. The status bar shows a live elapsed timer
  while an operation runs plus located/shared/hidden counts.
- **History** — explicitly save completed traces and scans to a local SQLite
  database, then browse, replay, delete or clear them.
- **Comparison & correlation** — load a selection of saved traces onto one map;
  hops that appear in two or more traces are marked as shared.
- **Collapsible panels** — click a splitter to fold the hop list or the DNS /
  subdomain panel away and give the space to the map; the collapsed panel leaves
  a slim rail with a chevron to bring it back. Drag a splitter to resize it.
- **Floating terminal windows** — every scan step (DNS, subdomains, crawl,
  trace, ports) opens its own draggable, resizable terminal window and streams
  verbose logs as it runs, so you can see exactly what each stage tried. Netcat
  sessions get their own windows too, and a general **Console** window shows
  overall activity. Every child window (log terminals, tool dialogs, netcat
  sessions) is flagged always-on-top, so the main window never covers them.
  Move, resize or close them freely; scan windows reset at the start of each
  operation.
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
| Linux | x86_64 | `tracemap-<version>-x86_64.AppImage`, `tracemap-<version>-linux-amd64.tar.gz`, `.deb`, `.rpm` |
| macOS | Apple Silicon (arm64) | `tracemap-<version>-darwin-arm64.zip` |
| Windows | x86_64 | `tracemap-<version>-windows-amd64.zip` |

The `.deb` and `.rpm` packages install the binary as `tracemap` (to `/usr/bin`),
a desktop entry and an icon. The AppImage is a single self-contained file that
bundles Qt6 — `chmod +x` it and run, no packages needed. It is built on Debian 12
so it only needs glibc 2.36, and it embeds `gh-releases-zsync` update information
with a matching `.zsync`, so AppImageUpdate can fetch later releases. The Windows
zip holds a single self-contained `tracemap.exe`: it is cross-compiled with
MinGW-w64 and a statically linked Qt6, so there are no Qt DLLs to ship, and built
with `-H windowsgui` so it opens without a console.

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which publishes a
GitHub release. Linux and macOS are built on their native runners against the
system Qt, and the AppImage is packaged in a Debian 12 container
(`scripts/build-appimage.sh`); Windows is cross-compiled on a Linux runner with
the cached MinGW-w64 + static Qt6 image in `win/`, so no Windows runner is
required.
CI (`.github/workflows/ci.yml`) runs `make check` on every push and pull request.

## How it works

Raw ICMP sockets are not available to a sandboxed UI, and the point is to measure
**your** network path, so the Go backend runs the system `traceroute`/`tracert`
binary locally and streams parsed hops to the UI. There is no HTTP server or
WebSocket: the backend is linked into the app. The Qt UI calls the Go methods
directly and installs an `EventSink` to receive typed events.

```
Qt6 window (native widgets + hand-painted offline vector map)
   │  Call: Trace, Scan, ScanPorts, NetConnect, NetSend, NetClose, AnalyzeDomain,
   │        ExportDomainReport, UnmaskTarget, UnmaskRulesPath, CreateUnmaskRules,
   │        ExportOriginReport, CheckTools, …
   │  Events (typed Go values): trace:hop, trace:geo, trace:done, scan:targets,
   │        scan:crawlPage, scan:crawlLog, portscan:open, net:data,
   │        domain:progress, origin:progress, origin:log, …
   ▼
Go backend (in-process)
   ├── tracerouter  spawn system traceroute/tracert, parse output
   ├── geolocator   IP → lat/lon, city, country, ASN (remote + SQLite + mmdb)
   ├── dnscheck     A/AAAA/CNAME/MX/NS/SOA lookup → trace targets
   ├── domaincheck  domain security report (RDAP/WHOIS, DNS, email auth, web/TLS)
   ├── subdomains   local subdomain discovery (brute force, PTR, SPF/SRV)
   ├── webcrawl     browser-UA HTTP crawl (front page + 1 level, robots, sitemap)
   ├── portscan     TCP connect / UDP port scan + banner/HTTP/TLS probing
   ├── origin       keyless origin discovery behind CDNs/proxies ("unmask")
   ├── netcat       interactive TCP sessions (optional TLS)
   ├── mapdata      embedded Natural Earth basemap + Web Mercator
   ├── mapview      QPainter map widget (layers, pan/zoom, hit-testing)
   └── history      saved traces/scans (SQLite snapshot store)
```

Every trace event carries a `target` id so the UI can group and colour
concurrent traces (`0` is the single-trace view; a scan assigns `1..N`).

## Requirements

- **Go** 1.26+
- **Qt6 development packages** and a C++ compiler (cgo)
  - Fedora: `sudo dnf install qt6-qtbase-devel gcc-c++`
  - Debian/Ubuntu: `sudo apt-get install qt6-base-dev g++`
  - macOS: `brew install qt`
- A system traceroute tool: `traceroute` (Linux/macOS), or a fallback of
  `tracepath`/`mtr`; Windows ships `tracert`. tracemap discovers the first one
  available on `PATH` or at conventional install locations. If none is found,
  the app warns before running a trace.

Run `make sysdeps` to verify the Qt6 build dependencies.

## Build & run

Everything goes through the `Makefile`. The map is drawn by our own QPainter
code, so there is no Node/webview build step.

```sh
make dev          # run the app directly from source
make build        # release binary -> build/bin/traceroute
make run          # build then launch
make check        # go vet + go test + go build
make sysdeps      # verify the Qt6 build dependencies
make clean        # remove build/bin
```

The first build compiles miqt's generated Qt6 bindings and can take a few
minutes; later builds are incremental.

## Usage

1. Type a hostname or IP into **TARGET / DOMAIN** and press **Trace**
   (or `Enter`).
   The **MAX HOPS** field in the toolbar sets the hop limit for traces.
2. Press **Scan** to open the scan options (DNS records, subdomain discovery,
   web crawl, and whether to auto-trace or review). Each target gets its own
   colour in the map's TRACES legend overlay and in the hop list. Uncheck a
   trace's checkbox in the **TARGETS** list to hide it from the map. As each step
   starts, it opens its own terminal window with verbose logs; discovered
   subdomains appear in the **SUBDOMAINS** list in the right sidebar, where you
   can select which ones to trace. Brute force can use the embedded wordlist or a
   custom file chosen with **Browse**.
3. Open **Tools ▾** and choose **Port scan** to scan the target, or right-click a
   target in the **TARGETS** list, a hop in the hop list, or a marker on the map
   and choose **Find open ports**. Pick the **Scope** (this host or all targets
   from the last scan), a **Preset** (Top 20/100/1000) or a **Custom range**,
   choose TCP or UDP, and optionally identify protocols. Open ports stream into
   the dialog as they are found; **Export report** saves the full scan context.
4. Open **Tools ▾** and choose **Domain analysis** for a security and reliability
   report on the current domain: WHOIS/RDAP registration, DNS and email-auth
   records, DNSSEC/CAA and web/TLS. The checklist shows pass/warn/fail with a
   score and grade; **Export** writes the full report to a text file.
5. Open **Tools ▾** and choose **Unmask target** (available once a scan has
   completed) to hunt for the origin behind a CDN/proxy. Use the built-in marker
   rules, or tick **Use custom rules** to load `unmask-rules.json` and
   **Create rules file** to copy the built-in defaults there, then run it: the
   dialog shows the proxied baseline and each candidate's verdict with its
   evidence, while a LIVE LOG pane streams the step-by-step detail. Confirmed and
   likely origins appear as 🏢 markers on the map; **Export report** writes a
   text report. **Cancel** stops a running run.
6. Open **Tools ▾** and choose **Netcat** (or use **Netcat…** in the port-scan
   row menu) to open a netcat session in its own floating window. Enter a host,
   port and connect timeout, optionally enable **TLS** and set an SNI name,
   connect, and type lines to send; output streams into the terminal. Press
   **Disconnect** when done (closing the window does too). Each session gets its
   own window. **Tools ▾ → Console** opens the general activity console.
7. Click a splitter between the map and a side panel to collapse or expand that
   panel — handy when you want more room for the map. Drag the splitter to
   resize instead.
8. Press **Cancel** to stop a running trace/scan; the domain, unmask, endpoint
   and port windows have their own **Cancel** buttons.
9. Press **+ History** to save the current view, and **History** to browse,
   load, correlate, delete or clear saved entries.
10. **Tools ▾** also opens the **GeoIP cache** (filter, delete single entries or
    clear all), the **Country IP blocks** browser (family and CIDR filters, a
    **Select database…** button to point at a GeoLite2 `.mmdb` file when none is
    auto-detected, plus export of a country's matching CIDR list), and
    **Endpoint analysis**
    (analyze the entered host plus any discovered subdomains, crawled pages or
    HTTP port services in bulk).

Hops that have no coordinates (private addresses, geolocation misses) stay in
the hop list but are omitted from the map. Located hops show their
latitude/longitude in the hop list and popup, each with an **Open in
OpenStreetMap** link. The target address is always shown as the final entry,
even if the trace never reaches it.

## History & comparison

- **Saving is explicit** — nothing is stored until you choose **+ History**.
- The **History** window lists every saved entry with its kind, target, path
  count, hop count and timestamp. Select one or more entries and choose
  **Load selected** to replay them, or **Correlate selected** to merge their
  hops into the correlation view.
- Hops present in two or more traces are highlighted as **shared** on the map
  and badged in the hop list — the quickest way to spot common paths and
  correlation points.
- Entries can be deleted individually (**Delete**) or all at once (**Clear all**).

## Configuration

Configuration is via environment variables, plus a couple of per-user files noted
below (the remembered GeoLite2 path).

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRACEROUTE_DB` | `tracemap.db` | SQLite database holding the geo cache and history; `off` disables persistence. |
| `TRACEROUTE_GEOIP_COUNTRY_DB` | auto-detected | Path to `GeoLite2-Country.mmdb` (country IP blocks browser). |
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

### Local GeoIP database (optional)

tracemap works without any local database — geolocation resolves through the
remote `ipwho.is` service and caches the replies in SQLite. A local MaxMind
GeoLite2 database is only a fallback for when that service is unreachable, and
it powers the **Country IP blocks** browser, so providing one is optional.

MaxMind distributes the databases as `.mmdb` files and requires a free account:

- GeoLite2 overview and download instructions:
  <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>
- Sign up for a free account / generate a license key:
  <https://www.maxmind.com/en/create-account>
- Download portal (after signing in):
  <https://www.maxmind.com/en/accounts/current/geoip/downloads>

Download `GeoLite2-Country.mmdb`, `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`,
then either drop them into a conventional directory (`/usr/share/GeoIP` and
similar — point elsewhere with `TRACEROUTE_GEOIP_DIR`) or set the path variables
in the table above. If tracemap still cannot find the database, open
**Tools ▾ → Country IP blocks** and click **Select database…** to pick the
`.mmdb` file with a native file dialog; the chosen path is remembered in
`~/.traceroute-geolite2` and reused on the next launch.

GeoLite2 data is distributed under MaxMind's
[GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula);
keep the downloaded databases up to date and include the required attribution
("This product includes GeoLite Data created by MaxMind, available from
<https://www.maxmind.com>") if you redistribute them.

### Unmask rules

The intermediary markers the **Unmask target** tool uses to recognise a proxy
response live in `unmask-rules.json` next to the database
(`~/.config/traceroute/unmask-rules.json` on Linux). It is optional: when it is
absent the built-in defaults are used. Tick **Use custom rules** in the dialog
to load it, or **Create rules file** to copy the built-in markers there for
editing. The file is plain JSON:

```json
{
  "headerNames": ["via", "x-cache", "age", "cf-ray"],
  "headerPrefixes": ["cdn-", "x-akamai-"]
}
```

| Bound method | Purpose |
| --- | --- |
| `UnmaskTarget(domain, customRules)` | Run origin discovery; `customRules` loads the rules file. |
| `UnmaskRulesPath()` | Where the rules file lives and whether it exists. |
| `CreateUnmaskRules()` | Copy the built-in rules there (asks before overwriting). |
| `ExportOriginReport(report)` | Save a text report via a native dialog. |

## Development

```
main.go                     Qt entry: QApplication + world load + run UI
app.go                      App struct + backend methods + event DTOs
emit.go                     EventSink + Dialogs interfaces
ui_app.go / ui_model.go     Qt controller, sidebar, map model, correlation
ui_logwindow.go             floating per-channel log windows
ui_dialogs.go               native Qt dialogs for the backend
ui_scan.go / ui_port.go     scan and port-scan windows
ui_tools.go                 domain / unmask / endpoint / GeoIP cache / blocks
ui_netcat.go                interactive TCP sessions
internal/mapdata/           embedded Natural Earth basemap + Web Mercator
internal/mapview/           hand-painted QPainter map widget
internal/tracerouter/       spawn system traceroute/tracert, parse output
internal/geolocator/        IP → geo (remote-first, SQLite cache, mmdb fallback)
internal/dnscheck/          A/AAAA/CNAME/MX/NS/SOA lookup → trace targets
internal/domaincheck/       domain security report (RDAP/WHOIS, DNS, email auth, web/TLS)
internal/subdomains/        local subdomain discovery (brute force, PTR, SPF/SRV)
internal/webcrawl/          browser-UA HTTP crawl (front page + 1 level, robots, sitemap)
internal/portscan/          TCP connect / UDP port scan + banner/HTTP/TLS probing
internal/origin/            keyless origin discovery behind CDNs/proxies ("unmask")
internal/netcat/            interactive TCP sessions (optional TLS)
internal/history/           saved traces/scans (SQLite snapshot store)
internal/appdata/           shared SQLite database path (tracemap.db)
```

### Testing

- Go tests live beside their packages and are table-driven.
- `tracerouter` tests use a fake shell binary — no real traceroute.
- `dnscheck` tests use a fake resolver — no network.
- `domaincheck` tests use an `httptest` RDAP/web server, a fake resolver and raw
  queryer, and a scripted WHOIS dialer — no external network.
- `subdomains` tests use a fake resolver and a temp SQLite cache — no network.
- `origin` tests use a fake resolver, an `httptest` TLS server and an injected
  dialer — no external network.
- `webcrawl` tests serve fixtures from an `httptest.Server` and dial it with a
  custom transport (plus a fake resolver) — no external network.
- `geolocator` tests use fake lookups/stores; real-database tests skip when
  absent.
- `history` tests use a temporary SQLite file — no network.
- `portscan` tests scan localhost listeners and `httptest` HTTP/TLS servers —
  no external network.
- `netcat` tests use localhost listeners and `httptest` TLS servers — no
  external network.

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
- Netcat sessions open a plain TCP (or TLS) socket from the Go standard library;
  no shell is involved. TLS certificate verification is intentionally skipped
  because the goal is service identification, not trust. Connect only to hosts
  you are authorised to use.
- Domain analysis makes outbound queries only to public sources: the IANA RDAP
  bootstrap and registry RDAP/WHOIS servers, the system DNS resolver, and the
  domain's own HTTP/HTTPS endpoints. No API keys are required.
- Unmask target is keyless and local-first: it mines the target's own DNS
  footprint and connects directly only to addresses that footprint already
  points to (never a guessed range). Direct probes skip TLS certificate
  verification because the origin is identified by fingerprint comparison, not
  trust. Run it only against targets you are authorised to test.
- No secrets or credentials are stored; all data stays in local SQLite files.

## License

[MIT](LICENSE) © 2026 Sinan Islekdemir

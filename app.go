package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"traceroute/internal/appdata"
	"traceroute/internal/dnscheck"
	"traceroute/internal/domaincheck"
	"traceroute/internal/geolocator"
	"traceroute/internal/history"
	"traceroute/internal/netcat"
	"traceroute/internal/netutil"
	"traceroute/internal/origin"
	"traceroute/internal/portscan"
	"traceroute/internal/subdomains"
	"traceroute/internal/tracerouter"
	"traceroute/internal/webcrawl"
)

// Event names emitted to the frontend.
const (
	EventHop            = "trace:hop"
	EventGeo            = "trace:geo"
	EventTarget         = "trace:target"
	EventTargetGeo      = "trace:targetGeo"
	EventDone           = "trace:done"
	EventError          = "trace:error"
	EventScanRecords    = "scan:records"
	EventScanTargets    = "scan:targets"
	EventScanDone       = "scan:done"
	EventSubdomains     = "scan:subdomains"
	EventSubdomainLog   = "scan:subdomainLog"
	EventScanProgress   = "scan:progress"
	EventCrawlPage      = "scan:crawlPage"
	EventCrawl          = "scan:crawl"
	EventCrawlLog       = "scan:crawlLog"
	EventPortOpen       = "portscan:open"
	EventPortProgress   = "portscan:progress"
	EventPortDone       = "portscan:done"
	EventPortError      = "portscan:error"
	EventNetData        = "net:data"
	EventNetClosed      = "net:closed"
	EventNetError       = "net:error"
	EventDomainProgress = "domain:progress"
	EventOriginProgress = "origin:progress"
	EventOriginLog      = "origin:log"
)

// scanConcurrency limits how many traces an advanced scan runs at once.
const scanConcurrency = 3

// TraceRequest starts a single trace.
type TraceRequest struct {
	Target  string `json:"target"`
	MaxHops int    `json:"maxHops"`
}

// ScanRequest starts an advanced scan of a domain.
type ScanRequest struct {
	Domain  string      `json:"domain"`
	MaxHops int         `json:"maxHops"`
	Options ScanOptions `json:"options"`
}

// ScanOptions controls what an advanced scan discovers and traces.
type ScanOptions struct {
	// ExpandNS follows NS/SOA nameservers recursively.
	ExpandNS bool `json:"expandNs"`
	// BruteForce probes the embedded wordlist of common subdomain labels.
	BruteForce bool `json:"bruteForce"`
	// WordlistPath optionally points brute force at a custom wordlist file
	// (newline-delimited labels) instead of the embedded list.
	WordlistPath string `json:"wordlistPath"`
	// PTR reverse-resolves discovered IPs into in-domain names.
	PTR bool `json:"ptr"`
	// Sweep24 also reverse-resolves the /24 around each IPv4 found.
	Sweep24 bool `json:"sweep24"`
	// Services parses SPF/DMARC TXT records and common SRV records.
	Services bool `json:"services"`
	// Crawl fetches the domain's frontpage, one level of same-site links,
	// robots.txt and sitemap.xml, discovering pages and subdomains.
	Crawl bool `json:"crawl"`
	// CrawlMaxPages caps how many pages the crawl fetches (0 uses the default).
	CrawlMaxPages int `json:"crawlMaxPages"`
	// AutoTrace adds discovered subdomains to the traced targets.
	AutoTrace bool `json:"autoTrace"`
	// MaxTargets caps how many addresses are traced (0 uses the default).
	MaxTargets int `json:"maxTargets"`
}

// TraceTargetsRequest traces an explicit set of hostnames, used after the user
// reviews discovered subdomains.
type TraceTargetsRequest struct {
	Domain  string   `json:"domain"`
	MaxHops int      `json:"maxHops"`
	Hosts   []string `json:"hosts"`
}

// ScanProgressEvent reports subdomain discovery progress.
type ScanProgressEvent struct {
	Phase string `json:"phase"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Found int    `json:"found"`
}

// CrawlLogEvent is a verbose crawl step, so the UI can show what was tried.
type CrawlLogEvent struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// PortScanTarget identifies one host in a multi-target port scan. Label is a
// human-friendly name (e.g. the scan target's hostname) shown beside the host.
type PortScanTarget struct {
	Label string `json:"label"`
	Host  string `json:"host"`
}

// PortScanRequest starts a port scan. Either Preset or PortRange selects the
// ports; PortRange wins when both are set. When Targets is non-empty each entry
// is scanned and Host is ignored; otherwise the single Host is scanned.
type PortScanRequest struct {
	Host        string           `json:"host"`
	Targets     []PortScanTarget `json:"targets"`
	Protocol    string           `json:"protocol"`
	Preset      string           `json:"preset"`
	PortRange   string           `json:"portRange"`
	Concurrency int              `json:"concurrency"`
	TimeoutMs   int              `json:"timeoutMs"`
	Probe       bool             `json:"probe"`
}

// PortOpenEvent reports one open port together with the target it belongs to.
type PortOpenEvent struct {
	Host   string          `json:"host"`
	Label  string          `json:"label,omitempty"`
	Result portscan.Result `json:"result"`
}

// PortScanProgressEvent reports how many ports have been probed so far for one
// target. Target/Targets give the target's 1-based index and the total count.
type PortScanProgressEvent struct {
	Host    string `json:"host"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Open    int    `json:"open"`
	Target  int    `json:"target"`
	Targets int    `json:"targets"`
}

// PortScanDoneEvent marks a port scan complete.
type PortScanDoneEvent struct {
	Host    string `json:"host"`
	Scanned int    `json:"scanned"`
	Open    int    `json:"open"`
	Targets int    `json:"targets"`
}

// PortScanRow is one open port in an exported port-scan report.
type PortScanRow struct {
	Host     string `json:"host"`
	Label    string `json:"label,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Banner   string `json:"banner,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
}

// PortScanTargetInfo identifies one resolved target in a port-scan report.
type PortScanTargetInfo struct {
	Label string `json:"label"`
	Host  string `json:"host"`
}

// PortScanReport captures the context of a port scan (the "initial data") and
// its open ports, for a human-readable export. The frontend assembles it from
// the scan options and the streamed results.
type PortScanReport struct {
	Target          string               `json:"target"`
	Scope           string               `json:"scope"`
	StartedAt       int64                `json:"startedAt"`
	DurationMs      int64                `json:"durationMs"`
	Protocol        string               `json:"protocol"`
	Ports           string               `json:"ports"`
	PortCount       int                  `json:"portCount"`
	Probe           bool                 `json:"probe"`
	Concurrency     int                  `json:"concurrency"`
	TimeoutMs       int                  `json:"timeoutMs"`
	Scanned         int                  `json:"scanned"`
	Open            int                  `json:"open"`
	Targets         int                  `json:"targets"`
	ResolvedTargets []PortScanTargetInfo `json:"resolvedTargets"`
	Rows            []PortScanRow        `json:"rows"`
}

// NetConnectRequest opens an interactive, line-oriented TCP session (netcat).
type NetConnectRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	TimeoutMs  int    `json:"timeoutMs"`
	TLS        bool   `json:"tls"`
	ServerName string `json:"serverName"`
}

// NetSession describes a live netcat session.
type NetSession struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	TLS    bool   `json:"tls"`
	Local  string `json:"local,omitempty"`
	Remote string `json:"remote,omitempty"`
}

// NetDataEvent carries a chunk of data received from a session's peer. Data is
// raw bytes; JSON encodes it as base64 so binary output survives intact.
type NetDataEvent struct {
	Session string `json:"session"`
	Data    []byte `json:"data"`
}

// NetClosedEvent reports that a session ended and why.
type NetClosedEvent struct {
	Session string `json:"session"`
	Reason  string `json:"reason"`
}

// HistorySaveRequest snapshots a completed trace or scan for later replay. The
// frontend builds it from the traces it currently holds, since geolocation
// results arrive asynchronously after the backend has finished the trace.
type HistorySaveRequest struct {
	Kind    string          `json:"kind"`
	Label   string          `json:"label"`
	MaxHops int             `json:"maxHops"`
	Traces  []history.Trace `json:"traces"`
}

// HopEvent is emitted for each hop as soon as its line is parsed. Target
// identifies which trace the hop belongs to; 0 is the single-trace view.
type HopEvent struct {
	Target int     `json:"target"`
	Hop    int     `json:"hop"`
	IP     string  `json:"ip,omitempty"`
	RTTMs  float64 `json:"rttMs,omitempty"`
}

// GeoEvent is emitted once a hop's IP has been geolocated.
type GeoEvent struct {
	Target int                `json:"target"`
	Hop    int                `json:"hop"`
	Geo    geolocator.GeoData `json:"geo"`
}

// TargetEvent announces the address a trace target resolved to.
type TargetEvent struct {
	Target int    `json:"target"`
	IP     string `json:"ip"`
}

// TargetGeoEvent carries the geolocation of a trace target.
type TargetGeoEvent struct {
	Target int                `json:"target"`
	Geo    geolocator.GeoData `json:"geo"`
}

// DoneEvent marks a single trace complete.
type DoneEvent struct {
	Target int `json:"target"`
	Hops   int `json:"hops"`
}

// ErrorEvent reports a failure. Target 0 means the whole operation failed.
type ErrorEvent struct {
	Target  int    `json:"target"`
	Message string `json:"message"`
	// Code classifies an actionable failure (currently "missing-tool").
	Code string `json:"code,omitempty"`
	// Hint carries platform-specific remediation for the failure.
	Hint string `json:"hint,omitempty"`
}

// ToolStatus reports whether the system traceroute tool required to run a
// trace is available, along with install guidance when it is not.
type ToolStatus struct {
	Available bool   `json:"available"`
	Tool      string `json:"tool,omitempty"`
	Message   string `json:"message,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// DomainProgressEvent reports the current phase of a domain analysis.
type DomainProgressEvent struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
}

// OriginProgressEvent reports the current phase of origin discovery.
type OriginProgressEvent struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
}

// OriginLogEvent is a verbose origin-discovery step, streamed to the terminal.
type OriginLogEvent struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// App is the Wails application backend.
type App struct {
	ctx    context.Context
	runner *tracerouter.Runner
	geo    *geolocator.Resolver
	hist   *history.Store
	subs   *subdomains.Store
	ports  *portscan.Scanner
	nc     *netcat.Manager
	domain *domaincheck.Analyzer

	// Each independent operation family owns a canceler so a run cannot
	// accidentally clear a newer run's cancellation handle.
	ops       canceler
	portOps   canceler
	domainOps canceler
	originOps canceler
}

// NewApp creates the application backend.
func NewApp() *App {
	app := &App{
		runner: tracerouter.NewRunner(),
		geo:    geolocator.NewResolver(),
		ports:  portscan.NewScanner(),
		nc:     netcat.NewManager(),
		domain: domaincheck.NewAnalyzer(),
	}

	store, err := history.Open(appdata.DefaultPath())
	switch {
	case err != nil:
		log.Printf("history: unavailable: %v", err)
	case store != nil:
		app.hist = store
		log.Printf("history: %s", store.Path())
	}

	subStore, err := subdomains.Open(appdata.DefaultPath())
	switch {
	case err != nil:
		log.Printf("subdomains: cache unavailable: %v", err)
	case subStore != nil:
		app.subs = subStore
	}

	return app
}

// startup stores the Wails runtime context used for emitting events.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// shutdown releases backend resources when the app exits.
func (a *App) shutdown(ctx context.Context) {
	_ = a.geo.Close()
	_ = a.hist.Close()
	_ = a.subs.Close()
	a.nc.CloseAll()
}

// CheckTools reports whether a supported traceroute tool is installed, so the
// UI can warn the user before they attempt a trace.
func (a *App) CheckTools() ToolStatus {
	path, err := tracerouter.Detect()
	if err != nil {
		return ToolStatus{
			Available: false,
			Message:   err.Error(),
			Hint:      tracerouter.InstallHint(),
		}
	}
	return ToolStatus{Available: true, Tool: filepath.Base(path)}
}

// PickWordlist opens a native file chooser and returns the selected wordlist
// path, or "" when the user cancels.
func (a *App) PickWordlist() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select subdomain wordlist",
		Filters: []runtime.FileFilter{
			{DisplayName: "Wordlists (*.txt, *.lst)", Pattern: "*.txt;*.lst"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
}

// begin cancels any running operation and returns a fresh context plus an end
// function that clears the cancellation state.
func (a *App) begin() (context.Context, func()) {
	return a.ops.begin(a.ctx)
}

// Trace runs a single traceroute. Results are emitted under target id 0.
func (a *App) Trace(req TraceRequest) error {
	ctx, end := a.begin()
	defer end()
	return a.runTrace(ctx, 0, req.Target, req.MaxHops)
}

// Scan resolves a domain's DNS records, optionally discovers subdomains, and
// traces the resulting addresses, emitting results tagged with a target id so
// the UI can group and colour them.
func (a *App) Scan(req ScanRequest) error {
	ctx, end := a.begin()
	defer end()

	opts := req.Options
	resolver := dnscheck.NewSystemResolver(net.DefaultResolver)
	records := dnscheck.LookupAll(ctx, resolver, req.Domain)
	if opts.ExpandNS {
		records = dnscheck.Expand(ctx, resolver, req.Domain, records, dnscheck.MaxNSDepth)
	}
	runtime.EventsEmit(a.ctx, EventScanRecords, records)

	var discovered []subdomains.Result
	var crawlResult webcrawl.Result
	dnsDiscovery := opts.BruteForce || opts.PTR || opts.Sweep24 || opts.Services

	var wordlist []string
	if path := strings.TrimSpace(opts.WordlistPath); path != "" && opts.BruteForce {
		words, err := subdomains.LoadWordlist(path)
		if err != nil {
			message := fmt.Sprintf("could not read subdomain wordlist: %v", err)
			runtime.EventsEmit(a.ctx, EventError, ErrorEvent{Target: 0, Message: message})
			return errors.New(message)
		}
		wordlist = words
	}

	if dnsDiscovery || opts.Crawl {
		// Announce each enabled step before it starts, so the UI opens its
		// terminal window even when a step fetches nothing or fails.
		if dnsDiscovery {
			runtime.EventsEmit(a.ctx, EventScanProgress, ScanProgressEvent{Phase: "subdomains"})
		}
		if opts.Crawl {
			runtime.EventsEmit(a.ctx, EventScanProgress, ScanProgressEvent{Phase: "crawl"})
		}

		var wg sync.WaitGroup
		if dnsDiscovery {
			wg.Add(1)
			go func() {
				defer wg.Done()
				discovered = subdomains.Discover(ctx, net.DefaultResolver, req.Domain, subdomains.Options{
					BruteForce: opts.BruteForce,
					PTR:        opts.PTR,
					Sweep24:    opts.Sweep24,
					Services:   opts.Services,
					Wordlist:   wordlist,
					OnProgress: func(phase string, done, total, found int) {
						runtime.EventsEmit(a.ctx, EventScanProgress, ScanProgressEvent{
							Phase: phase, Done: done, Total: total, Found: found,
						})
					},
					OnLog: func(level, message string) {
						runtime.EventsEmit(a.ctx, EventSubdomainLog, CrawlLogEvent{Level: level, Message: message})
					},
				}, a.subs)
			}()
		}
		if opts.Crawl {
			wg.Add(1)
			go func() {
				defer wg.Done()
				crawlResult = webcrawl.Crawl(ctx, req.Domain, webcrawl.Options{
					MaxPages: opts.CrawlMaxPages,
					OnPage: func(page webcrawl.Page) {
						runtime.EventsEmit(a.ctx, EventCrawlPage, page)
					},
					OnProgress: func(done, total, found int) {
						runtime.EventsEmit(a.ctx, EventScanProgress, ScanProgressEvent{
							Phase: "crawl", Done: done, Total: total, Found: found,
						})
					},
					OnLog: func(level, message string) {
						runtime.EventsEmit(a.ctx, EventCrawlLog, CrawlLogEvent{Level: level, Message: message})
					},
				})
			}()
		}
		wg.Wait()

		if opts.Crawl {
			crawlSubs := crawlSubdomainResults(crawlResult.Subdomains)
			persistCrawlSubdomains(ctx, a.subs, req.Domain, crawlSubs, discovered)
			discovered = mergeSubdomainResults(discovered, crawlSubs)
			crawlResult.Pages = stripPageBodies(crawlResult.Pages)
			runtime.EventsEmit(a.ctx, EventCrawl, crawlResult)
		}
		if discovered == nil {
			discovered = []subdomains.Result{}
		}
		runtime.EventsEmit(a.ctx, EventSubdomains, discovered)
	}

	limit := opts.MaxTargets
	if limit <= 0 {
		limit = dnscheck.MaxTargets
	}
	targets := dnscheck.AllTargets(ctx, resolver, req.Domain, records)
	if opts.AutoTrace && len(discovered) > 0 {
		targets = appendSubdomainTargets(targets, discovered, limit)
	}
	targets = netutil.Cap(targets, limit)
	targets = filterUnroutable(targets)
	if len(targets) == 0 {
		message := fmt.Sprintf("no routable address records found for %s", req.Domain)
		runtime.EventsEmit(a.ctx, EventError, ErrorEvent{Target: 0, Message: message})
		return errors.New(message)
	}

	return a.traceScan(ctx, targets, req.MaxHops)
}

// TraceTargets traces an explicit set of hostnames, used after the user reviews
// discovered subdomains and picks which to trace.
func (a *App) TraceTargets(req TraceTargetsRequest) error {
	ctx, end := a.begin()
	defer end()

	targets := make([]dnscheck.Target, 0, len(req.Hosts))
	for _, host := range req.Hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			targets = append(targets, dnscheck.Target{
				ID: len(targets) + 1, Kind: "SUB", Label: host, IP: ip.String(),
			})
		}
	}
	targets = filterUnroutable(targets)
	if len(targets) == 0 {
		message := "no routable addresses to trace for the selected subdomains"
		runtime.EventsEmit(a.ctx, EventError, ErrorEvent{Target: 0, Message: message})
		return errors.New(message)
	}

	return a.traceScan(ctx, targets, req.MaxHops)
}

// traceScan announces the targets and runs their traces with bounded
// concurrency, then reports completion.
func (a *App) traceScan(ctx context.Context, targets []dnscheck.Target, maxHops int) error {
	runtime.EventsEmit(a.ctx, EventScanTargets, targets)

	sem := make(chan struct{}, scanConcurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t dnscheck.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			_ = a.runTrace(ctx, t.ID, t.IP, maxHops)
		}(target)
	}
	wg.Wait()

	runtime.EventsEmit(a.ctx, EventScanDone, len(targets))
	return nil
}

// appendSubdomainTargets adds discovered subdomain addresses to targets until
// limit is reached, skipping duplicates.
func appendSubdomainTargets(targets []dnscheck.Target, discovered []subdomains.Result, limit int) []dnscheck.Target {
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		seen[target.IP] = true
	}
	for _, result := range discovered {
		for _, ip := range result.IPs {
			if len(targets) >= limit {
				return targets
			}
			if seen[ip] {
				continue
			}
			seen[ip] = true
			targets = append(targets, dnscheck.Target{
				ID: len(targets) + 1, Kind: "SUB", Label: result.Name, IP: ip,
			})
		}
	}
	return targets
}

// stripPageBodies returns copies of pages with their raw bodies removed, so the
// final scan:crawl event stays small: the full HTML already streamed per page
// through scan:crawlPage.
func stripPageBodies(pages []webcrawl.Page) []webcrawl.Page {
	out := make([]webcrawl.Page, len(pages))
	for i, page := range pages {
		page.HTML = ""
		out[i] = page
	}
	return out
}

// crawlSubdomainResults converts crawl-discovered hostnames into subdomain
// results tagged with the "crawl" source.
func crawlSubdomainResults(found []webcrawl.Subdomain) []subdomains.Result {
	results := make([]subdomains.Result, 0, len(found))
	for _, sub := range found {
		if sub.Name == "" {
			continue
		}
		// Normalise to a non-nil slice so the JSON payload carries [] not null.
		results = append(results, subdomains.Result{Name: sub.Name, Source: "crawl", IPs: netutil.MergeUnique(nil, sub.IPs)})
	}
	return results
}

// persistCrawlSubdomains caches crawl results, skipping names already known to
// DNS discovery so the "crawl" source never overwrites a more specific one.
func persistCrawlSubdomains(ctx context.Context, store *subdomains.Store, domain string, crawl, dns []subdomains.Result) {
	if store == nil || len(crawl) == 0 {
		return
	}
	known := make(map[string]bool, len(dns))
	for _, result := range dns {
		known[result.Name] = true
	}
	fresh := make([]subdomains.Result, 0, len(crawl))
	for _, result := range crawl {
		if !known[result.Name] {
			fresh = append(fresh, result)
		}
	}
	if len(fresh) > 0 {
		_ = store.Save(ctx, domain, fresh)
	}
}

// mergeSubdomainResults merges extra into base by name, unioning IPs while
// keeping the source already recorded for a name.
func mergeSubdomainResults(base, extra []subdomains.Result) []subdomains.Result {
	if len(extra) == 0 {
		return base
	}
	index := make(map[string]int, len(base))
	for i, result := range base {
		index[result.Name] = i
	}
	for _, result := range extra {
		result.IPs = netutil.MergeUnique(nil, result.IPs)
		if at, ok := index[result.Name]; ok {
			base[at].IPs = netutil.MergeUnique(base[at].IPs, result.IPs)
			continue
		}
		index[result.Name] = len(base)
		base = append(base, result)
	}
	return base
}

// portScanHostConcurrency bounds how many targets a multi-target port scan
// probes at once. Each target already fans out over its ports internally.
const portScanHostConcurrency = 4

// ScanPorts probes one or more targets for open ports, emitting each open port
// as it is found. Results stream through portscan:open/portscan:progress and
// finish with portscan:done (or portscan:error).
func (a *App) ScanPorts(req PortScanRequest) error {
	ctx, end := a.portOps.begin(a.ctx)
	defer end()

	targets := normalizePortScanTargets(req)
	if len(targets) == 0 {
		message := "no host to scan"
		runtime.EventsEmit(a.ctx, EventPortError, ErrorEvent{Target: 0, Message: message})
		return errors.New(message)
	}

	ports, err := resolveScanPorts(req)
	if err != nil {
		runtime.EventsEmit(a.ctx, EventPortError, ErrorEvent{Target: 0, Message: err.Error()})
		return err
	}

	opts := portscan.Options{
		Protocol:    req.Protocol,
		Ports:       ports,
		Concurrency: req.Concurrency,
		Timeout:     time.Duration(req.TimeoutMs) * time.Millisecond,
		Probe:       req.Probe,
		Jitter:      portscan.DefaultJitter,
	}

	var (
		open    int64
		mu      sync.Mutex
		scanErr error
	)
	sem := make(chan struct{}, portScanHostConcurrency)
	var wg sync.WaitGroup
	for index, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, tgt PortScanTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			_, err := a.ports.Scan(ctx, tgt.Host, opts, portscan.Observer{
				OnOpen: func(result portscan.Result) {
					atomic.AddInt64(&open, 1)
					runtime.EventsEmit(a.ctx, EventPortOpen, PortOpenEvent{
						Host: tgt.Host, Label: tgt.Label, Result: result,
					})
				},
				OnProgress: func(done, total, openCount int) {
					runtime.EventsEmit(a.ctx, EventPortProgress, PortScanProgressEvent{
						Host: tgt.Host, Done: done, Total: total, Open: openCount,
						Target: idx + 1, Targets: len(targets),
					})
				},
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				mu.Lock()
				if scanErr == nil {
					scanErr = err
				}
				mu.Unlock()
			}
		}(index, target)
	}
	wg.Wait()

	if scanErr != nil {
		runtime.EventsEmit(a.ctx, EventPortError, ErrorEvent{Target: 0, Message: scanErr.Error()})
		return scanErr
	}
	runtime.EventsEmit(a.ctx, EventPortDone, PortScanDoneEvent{
		Host: targets[0].Host, Scanned: len(ports), Open: int(atomic.LoadInt64(&open)),
		Targets: len(targets),
	})
	return nil
}

// normalizePortScanTargets resolves a request into the distinct, non-empty
// targets to scan. When Targets is empty the single Host is used.
func normalizePortScanTargets(req PortScanRequest) []PortScanTarget {
	source := req.Targets
	if len(source) == 0 {
		source = []PortScanTarget{{Label: req.Host, Host: req.Host}}
	}

	seen := make(map[string]struct{}, len(source))
	out := make([]PortScanTarget, 0, len(source))
	for _, target := range source {
		host := strings.TrimSpace(target.Host)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		label := strings.TrimSpace(target.Label)
		if label == "" {
			label = host
		}
		out = append(out, PortScanTarget{Label: label, Host: host})
	}
	return out
}

// resolveScanPorts expands a request into a concrete, validated port list.
func resolveScanPorts(req PortScanRequest) ([]int, error) {
	if strings.TrimSpace(req.PortRange) != "" {
		return portscan.ParsePorts(req.PortRange)
	}
	return portscan.PresetPorts(req.Preset)
}

// NetConnect opens an interactive TCP session and streams the peer's output
// through net:data events until NetClose is called or the peer disconnects
// (net:closed). Sessions are independent of the trace/scan cancel model.
func (a *App) NetConnect(req NetConnectRequest) (NetSession, error) {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		message := "no host to connect to"
		runtime.EventsEmit(a.ctx, EventNetError, ErrorEvent{Target: 0, Message: message})
		return NetSession{}, errors.New(message)
	}

	session, err := a.nc.Connect(a.ctx, netcat.Options{
		Host:       host,
		Port:       req.Port,
		Timeout:    time.Duration(req.TimeoutMs) * time.Millisecond,
		TLS:        req.TLS,
		ServerName: req.ServerName,
	}, netcat.Observer{
		OnData: func(id string, data []byte) {
			runtime.EventsEmit(a.ctx, EventNetData, NetDataEvent{Session: id, Data: data})
		},
		OnClose: func(id, reason string) {
			runtime.EventsEmit(a.ctx, EventNetClosed, NetClosedEvent{Session: id, Reason: reason})
		},
	})
	if err != nil {
		runtime.EventsEmit(a.ctx, EventNetError, ErrorEvent{Target: 0, Message: err.Error()})
		return NetSession{}, err
	}

	return NetSession{
		ID: session.ID, Host: session.Host, Port: session.Port,
		TLS: session.TLS, Local: session.Local, Remote: session.Remote,
	}, nil
}

// NetSend writes data to a live netcat session.
func (a *App) NetSend(sessionID string, data string) error {
	return a.nc.Send(sessionID, data)
}

// NetClose ends a netcat session.
func (a *App) NetClose(sessionID string) error {
	return a.nc.Close(sessionID)
}

// AnalyzeDomain builds a security and reliability report for a domain. It runs
// with its own cancellation context, independent of the trace/scan model, so it
// neither cancels nor is cancelled by traces. Progress is streamed through
// domain:progress; the finished report is the return value.
func (a *App) AnalyzeDomain(domain string) (domaincheck.Report, error) {
	ctx, end := a.domainOps.begin(a.ctx)
	defer end()

	report, err := a.domain.Analyze(ctx, domain, func(phase, message string) {
		runtime.EventsEmit(a.ctx, EventDomainProgress, DomainProgressEvent{Phase: phase, Message: message})
	})
	if err != nil {
		return report, err
	}
	return report, nil
}

// CancelDomainAnalysis stops a running domain analysis, if any.
func (a *App) CancelDomainAnalysis() {
	a.domainOps.stop()
}

// ExportDomainReport renders the report as text and writes it to a path chosen
// by the user, returning the path (empty when the dialog is cancelled).
func (a *App) ExportDomainReport(report domaincheck.Report) (string, error) {
	name := strings.TrimSpace(report.Domain)
	if name == "" {
		name = "domain"
	}
	return a.saveTextReport("Save domain analysis report", name+"-domain-report.txt", domaincheck.FormatReport(report))
}

// saveTextReport asks the user for a destination and writes content there. It
// returns the chosen path, or "" when the dialog is cancelled.
func (a *App) saveTextReport(title, defaultName, content string) (string, error) {
	return a.saveReport(title, defaultName, "Text files (*.txt)", "*.txt", content)
}

// saveReport asks the user for a destination matching the supplied filter and
// writes content there. It returns the chosen path, or "" when cancelled.
func (a *App) saveReport(title, defaultName, displayName, pattern, content string) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           title,
		DefaultFilename: defaultName,
		Filters: []runtime.FileFilter{
			{DisplayName: displayName, Pattern: pattern},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// UnmaskTarget discovers the origin address behind a CDN or reverse proxy. It
// combines the domain's DNS footprint (including the most recent scan's
// subdomains) with direct fingerprint verification. It runs with its own
// cancellation context, independent of traces and scans. When customRules is
// true the intermediary-marker rules are read from the user's rules file;
// otherwise the built-in defaults are used.
func (a *App) UnmaskTarget(domain string, customRules bool) (origin.Report, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return origin.Report{}, errors.New("no target domain provided")
	}

	ctx, end := a.originOps.begin(a.ctx)
	defer end()

	var subs []subdomains.Result
	if a.subs != nil {
		if cached, err := a.subs.Load(ctx, domain); err == nil {
			subs = cached
		}
	}

	rules := origin.DefaultRules()
	if customRules {
		loaded, err := origin.LoadRules(unmaskRulesPath())
		if err != nil {
			runtime.EventsEmit(a.ctx, EventError, ErrorEvent{
				Target:  0,
				Message: fmt.Sprintf("unmask rules file could not be read, using defaults: %v", err),
			})
		}
		rules = loaded
	}

	report := origin.Discover(ctx, domain, origin.Options{
		Subdomains: subs,
		Rules:      rules,
		OnProgress: func(phase, message string) {
			runtime.EventsEmit(a.ctx, EventOriginProgress, OriginProgressEvent{Phase: phase, Message: message})
		},
		OnLog: func(level, message string) {
			runtime.EventsEmit(a.ctx, EventOriginLog, OriginLogEvent{Level: level, Message: message})
		},
	})

	for i := range report.Origins {
		verdict := report.Origins[i].Verdict
		if verdict != origin.VerdictConfirmed && verdict != origin.VerdictLikely {
			continue
		}
		if data, err := a.geo.ResolveOne(ctx, report.Origins[i].IP); err == nil {
			report.Origins[i].Geo = data
		}
	}
	return report, nil
}

// UnmaskRulesInfo is the location and existence of the user's unmask rules file.
type UnmaskRulesInfo struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
}

// UnmaskRulesPath reports where the unmask rules file lives and whether it
// exists, so the UI can offer to load or create it.
func (a *App) UnmaskRulesPath() UnmaskRulesInfo {
	path := unmaskRulesPath()
	if path == "" {
		return UnmaskRulesInfo{}
	}
	_, err := os.Stat(path)
	return UnmaskRulesInfo{Path: path, Exists: err == nil}
}

// CreateUnmaskRules copies the built-in marker rules to the user's rules file
// for maintenance, asking before overwriting an existing file. It returns the
// path (empty when the user cancels).
func (a *App) CreateUnmaskRules() (string, error) {
	path := unmaskRulesPath()
	if path == "" {
		return "", errors.New("no configuration directory available")
	}
	if _, err := os.Stat(path); err == nil {
		choice, err := runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
			Type:    runtime.QuestionDialog,
			Title:   "Unmask rules",
			Message: "The rules file already exists. Overwrite it with the built-in defaults?",
			Buttons: []string{"Overwrite", "Cancel"},
		})
		if err != nil {
			return "", err
		}
		if choice != "Overwrite" {
			return "", nil
		}
	}
	if err := origin.SaveRules(path, origin.DefaultRules()); err != nil {
		return "", err
	}
	return path, nil
}

// unmaskRulesPath is the user's unmask marker rules file.
func unmaskRulesPath() string {
	dir := appdata.ConfigDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "unmask-rules.json")
}

// CancelUnmaskTarget stops a running origin discovery, if any.
func (a *App) CancelUnmaskTarget() {
	a.originOps.stop()
}

// ExportOriginReport renders the report as text and writes it to a path chosen
// by the user, returning the path (empty when the dialog is cancelled).
func (a *App) ExportOriginReport(report origin.Report) (string, error) {
	name := strings.TrimSpace(report.Domain)
	if name == "" {
		name = "target"
	}
	return a.saveTextReport("Save origin discovery report", name+"-origin-report.txt", origin.FormatReport(report))
}

// ExportPortScanReport writes the supplied scan context and open ports as a
// human-readable text report to a path chosen by the user, returning the path
// (empty when cancelled).
func (a *App) ExportPortScanReport(report PortScanReport) (string, error) {
	name := strings.TrimSpace(report.Target)
	if name == "" {
		name = "portscan"
	}
	name = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(name)
	return a.saveTextReport("Save port scan report", name+"-portscan.txt", formatPortScanReport(report))
}

// formatPortScanReport renders a port scan as a verbose, human-readable
// document: the scan context ("initial data"), a summary, and the open ports
// grouped per target.
func formatPortScanReport(report PortScanReport) string {
	var b strings.Builder
	b.WriteString("PORT SCAN REPORT\n")
	b.WriteString("================\n\n")

	fmt.Fprintf(&b, "Target:       %s\n", fallbackReportValue(report.Target, "—"))
	fmt.Fprintf(&b, "Scope:        %s\n", reportScope(report))
	fmt.Fprintf(&b, "Started:      %s\n", formatReportTime(report.StartedAt))
	fmt.Fprintf(&b, "Duration:     %s\n", formatReportDuration(report.DurationMs))
	fmt.Fprintf(&b, "Protocol:     %s\n", fallbackReportValue(report.Protocol, "—"))
	fmt.Fprintf(&b, "Ports:        %s\n", reportPortsLabel(report))
	probe := "disabled"
	if report.Probe {
		probe = "enabled"
	}
	fmt.Fprintf(&b, "Identify:     %s\n", probe)
	fmt.Fprintf(&b, "Pacing:       concurrency %d · timeout %dms\n", report.Concurrency, report.TimeoutMs)

	targets := reportTargets(report)
	if len(targets) > 0 {
		b.WriteString("\nTARGETS\n-------\n")
		for _, target := range targets {
			fmt.Fprintf(&b, "  %-18s %s\n", target.Host, target.Label)
		}
	}

	b.WriteString("\nSUMMARY\n-------\n")
	fmt.Fprintf(&b, "  %d %s scanned\n", report.Targets, plural(report.Targets, "target", "targets"))
	fmt.Fprintf(&b, "  %d open %s\n", report.Open, plural(report.Open, "port", "ports"))
	fmt.Fprintf(&b, "  %d ports scanned per target\n", report.Scanned)

	b.WriteString("\nOPEN PORTS\n----------\n")
	if len(report.Rows) == 0 {
		b.WriteString("\n  No open ports were found.\n")
		return b.String()
	}
	byHost := make(map[string][]PortScanRow, len(targets))
	for _, row := range report.Rows {
		byHost[row.Host] = append(byHost[row.Host], row)
	}
	for _, target := range targets {
		rows := byHost[target.Host]
		delete(byHost, target.Host)
		b.WriteString("\n")
		b.WriteString(targetHeading(target))
		b.WriteString("\n")
		if len(rows) == 0 {
			b.WriteString("  no open ports\n")
			continue
		}
		sortPortScanRows(rows)
		for _, row := range rows {
			b.WriteString(formatPortScanRow(row))
		}
	}
	// Any rows for hosts that were not listed as resolved targets.
	remaining := make([]string, 0, len(byHost))
	for host := range byHost {
		remaining = append(remaining, host)
	}
	sort.Strings(remaining)
	for _, host := range remaining {
		rows := byHost[host]
		sortPortScanRows(rows)
		b.WriteString("\n")
		b.WriteString(host)
		b.WriteString("\n")
		for _, row := range rows {
			b.WriteString(formatPortScanRow(row))
		}
	}
	return b.String()
}

// reportTargets returns the resolved targets in report order, falling back to
// the hosts seen in the rows when none were supplied.
func reportTargets(report PortScanReport) []PortScanTargetInfo {
	if len(report.ResolvedTargets) > 0 {
		return report.ResolvedTargets
	}
	seen := make(map[string]bool)
	var out []PortScanTargetInfo
	for _, row := range report.Rows {
		if seen[row.Host] {
			continue
		}
		seen[row.Host] = true
		out = append(out, PortScanTargetInfo{Label: row.Label, Host: row.Host})
	}
	return out
}

func reportScope(report PortScanReport) string {
	if report.Scope != "" {
		return report.Scope
	}
	if report.Targets > 1 {
		return fmt.Sprintf("all targets (%d)", report.Targets)
	}
	return "single host"
}

func reportPortsLabel(report PortScanReport) string {
	label := fallbackReportValue(report.Ports, "—")
	if report.PortCount > 0 {
		label = fmt.Sprintf("%s (%d ports)", label, report.PortCount)
	}
	return label
}

func targetHeading(target PortScanTargetInfo) string {
	if target.Label == "" || target.Label == target.Host {
		return target.Host
	}
	return fmt.Sprintf("%s (%s)", target.Label, target.Host)
}

// formatPortScanRow renders one open port plus its identification details.
func formatPortScanRow(row PortScanRow) string {
	var b strings.Builder
	parts := []string{
		fmt.Sprintf("%-10s", fmt.Sprintf("%d/%s", row.Port, row.Protocol)),
		"open",
		fmt.Sprintf("%-10s", row.Service),
	}
	if row.Product != "" {
		parts = append(parts, row.Product)
	}
	line := "  " + strings.Join(parts, " ")
	if row.TLS {
		line += "  [TLS]"
	}
	b.WriteString(strings.TrimRight(line, " "))
	b.WriteByte('\n')
	if row.Detail != "" {
		fmt.Fprintf(&b, "      detail: %s\n", oneLine(row.Detail))
	}
	if row.Banner != "" && row.Banner != row.Detail {
		fmt.Fprintf(&b, "      banner: %s\n", oneLine(row.Banner))
	}
	return b.String()
}

func sortPortScanRows(rows []PortScanRow) {
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Port < rows[j].Port
	})
}

func formatReportTime(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04:05")
}

func formatReportDuration(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	d := time.Duration(ms) * time.Millisecond
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func fallbackReportValue(value, alt string) string {
	if strings.TrimSpace(value) == "" {
		return alt
	}
	return value
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// oneLine collapses whitespace so a multi-line banner stays on one report line.
func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// Cancel stops the running trace or scan, if any.
func (a *App) Cancel() {
	a.ops.stop()
}

// CancelPortScan stops a running port scan, if any. Port scans use their own
// cancellation context so they neither stop nor are stopped by traces/scans.
func (a *App) CancelPortScan() {
	a.portOps.stop()
}

// SaveHistory stores the supplied snapshot of the current traces and returns
// its history id. Saving is explicit; nothing is persisted automatically.
func (a *App) SaveHistory(req HistorySaveRequest) (int64, error) {
	if a.hist == nil {
		return 0, errors.New("history is disabled")
	}
	if req.Label == "" {
		return 0, errors.New("history entry needs a label")
	}
	if len(req.Traces) == 0 {
		return 0, errors.New("nothing to save")
	}
	kind := req.Kind
	if kind == "" {
		kind = "trace"
	}

	return a.hist.Save(a.ctx, history.Entry{
		Kind:    kind,
		Label:   req.Label,
		MaxHops: req.MaxHops,
		Traces:  req.Traces,
	})
}

// ListHistory returns the saved entries, newest first.
func (a *App) ListHistory() ([]history.Summary, error) {
	return a.hist.List(a.ctx)
}

// LoadHistory returns the full entries for ids so the UI can replay them.
func (a *App) LoadHistory(ids []int64) ([]history.Entry, error) {
	return a.hist.Load(a.ctx, ids)
}

// DeleteHistory removes a single saved entry.
func (a *App) DeleteHistory(id int64) error {
	return a.hist.Delete(a.ctx, id)
}

// ClearHistory removes every saved entry.
func (a *App) ClearHistory() error {
	return a.hist.Clear(a.ctx)
}

// GeoCacheInfo reports the state of the persistent geolocation cache: whether
// it is enabled, where it lives and how many replies it holds.
func (a *App) GeoCacheInfo() geolocator.CacheInfo {
	return a.geo.CacheInfo(a.ctx)
}

// ListGeoCache returns every cached geolocation reply, newest first.
func (a *App) ListGeoCache() ([]geolocator.CacheEntry, error) {
	return a.geo.CacheEntries(a.ctx)
}

// DeleteGeoCacheEntry removes a single IP from the geolocation cache.
func (a *App) DeleteGeoCacheEntry(ip string) error {
	return a.geo.DeleteCacheEntry(a.ctx, ip)
}

// ClearGeoCache removes every cached geolocation reply.
func (a *App) ClearGeoCache() error {
	return a.geo.ClearCache(a.ctx)
}

// filterUnroutable drops IPv6 targets when this host has no global IPv6
// address, since tracing them can only fail. Target ids are renumbered so the
// UI's colours stay contiguous.
func filterUnroutable(targets []dnscheck.Target) []dnscheck.Target {
	if hasIPv6() {
		return targets
	}
	kept := targets[:0]
	for _, target := range targets {
		if ip := net.ParseIP(target.IP); ip != nil && ip.To4() == nil {
			continue
		}
		target.ID = len(kept) + 1
		kept = append(kept, target)
	}
	return kept
}

// hasIPv6 reports whether the host has a usable global IPv6 address.
func hasIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.To4() != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return true
	}
	return false
}

// runTrace executes one traceroute and emits its events under target.
func (a *App) runTrace(ctx context.Context, target int, host string, maxHops int) error {
	opts := tracerouter.Options{MaxHops: maxHops}

	count := 0
	err := a.runner.ExecuteStream(ctx, host, opts, tracerouter.Observer{
		OnHop: func(h tracerouter.Hop) {
			count++
			runtime.EventsEmit(a.ctx, EventHop, HopEvent{
				Target: target,
				Hop:    h.Number,
				IP:     h.IP,
				RTTMs:  float64(h.BestRTT()) / float64(time.Millisecond),
			})
			if h.Responded() {
				go a.emitGeo(ctx, target, h.Number, h.IP)
			}
		},
		OnTarget: func(ip string) {
			runtime.EventsEmit(a.ctx, EventTarget, TargetEvent{Target: target, IP: ip})
			go a.emitTargetGeo(ctx, target, ip)
		},
	})

	switch {
	case err == nil, errors.Is(err, context.Canceled):
		runtime.EventsEmit(a.ctx, EventDone, DoneEvent{Target: target, Hops: count})
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		runtime.EventsEmit(a.ctx, EventError, ErrorEvent{Target: target, Message: "trace timed out"})
		return err
	default:
		event := ErrorEvent{Target: target, Message: err.Error()}
		if tracerouter.IsMissingTool(err) {
			event.Code = "missing-tool"
			event.Hint = tracerouter.InstallHint()
		}
		runtime.EventsEmit(a.ctx, EventError, event)
		return err
	}
}

// resolveGeo resolves an IP for event emission. A failed lookup still returns
// ok=true with empty GeoData so the UI can stop showing the address as pending;
// ok=false means the caller's context ended and nothing should be emitted.
func (a *App) resolveGeo(ctx context.Context, ip string) (geolocator.GeoData, bool) {
	data, err := a.geo.ResolveOne(ctx, ip)
	if err != nil {
		if ctx.Err() != nil {
			return geolocator.GeoData{}, false
		}
		return geolocator.GeoData{}, true
	}
	return data, true
}

// emitGeo resolves a hop IP and emits an EventGeo. Lookups run in the
// background so a slow geolocation service never delays the trace stream. A
// failed lookup is still emitted (with Resolved false) so the UI can stop
// showing the hop as pending.
func (a *App) emitGeo(ctx context.Context, target, hop int, ip string) {
	data, ok := a.resolveGeo(ctx, ip)
	if !ok {
		return
	}
	runtime.EventsEmit(a.ctx, EventGeo, GeoEvent{Target: target, Hop: hop, Geo: data})
}

// emitTargetGeo resolves the target address and emits an EventTargetGeo so the
// destination can be placed on the map even when the trace never reaches it.
func (a *App) emitTargetGeo(ctx context.Context, target int, ip string) {
	data, ok := a.resolveGeo(ctx, ip)
	if !ok {
		return
	}
	runtime.EventsEmit(a.ctx, EventTargetGeo, TargetGeoEvent{Target: target, Geo: data})
}

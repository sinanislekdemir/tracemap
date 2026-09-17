package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"traceroute/internal/appdata"
	"traceroute/internal/dnscheck"
	"traceroute/internal/geolocator"
	"traceroute/internal/history"
	"traceroute/internal/portscan"
	"traceroute/internal/subdomains"
	"traceroute/internal/tracerouter"
)

// Event names emitted to the frontend.
const (
	EventHop          = "trace:hop"
	EventGeo          = "trace:geo"
	EventTarget       = "trace:target"
	EventTargetGeo    = "trace:targetGeo"
	EventDone         = "trace:done"
	EventError        = "trace:error"
	EventScanRecords  = "scan:records"
	EventScanTargets  = "scan:targets"
	EventScanDone     = "scan:done"
	EventSubdomains   = "scan:subdomains"
	EventScanProgress = "scan:progress"
	EventPortOpen     = "portscan:open"
	EventPortProgress = "portscan:progress"
	EventPortDone     = "portscan:done"
	EventPortError    = "portscan:error"
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
	// PTR reverse-resolves discovered IPs into in-domain names.
	PTR bool `json:"ptr"`
	// Sweep24 also reverse-resolves the /24 around each IPv4 found.
	Sweep24 bool `json:"sweep24"`
	// Services parses SPF/DMARC TXT records and common SRV records.
	Services bool `json:"services"`
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

// PortScanRequest starts a port scan of a host. Either Preset or PortRange
// selects the ports; PortRange wins when both are set.
type PortScanRequest struct {
	Host        string `json:"host"`
	Protocol    string `json:"protocol"`
	Preset      string `json:"preset"`
	PortRange   string `json:"portRange"`
	Concurrency int    `json:"concurrency"`
	TimeoutMs   int    `json:"timeoutMs"`
	Probe       bool   `json:"probe"`
}

// PortScanProgressEvent reports how many ports have been probed so far.
type PortScanProgressEvent struct {
	Host  string `json:"host"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Open  int    `json:"open"`
}

// PortScanDoneEvent marks a port scan complete.
type PortScanDoneEvent struct {
	Host    string `json:"host"`
	Scanned int    `json:"scanned"`
	Open    int    `json:"open"`
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

// App is the Wails application backend.
type App struct {
	ctx    context.Context
	runner *tracerouter.Runner
	geo    *geolocator.Resolver
	hist   *history.Store
	subs   *subdomains.Store
	ports  *portscan.Scanner

	mu     sync.Mutex
	gen    uint64
	cancel context.CancelFunc
}

// NewApp creates the application backend.
func NewApp() *App {
	app := &App{
		runner: tracerouter.NewRunner(),
		geo:    geolocator.NewResolver(),
		ports:  portscan.NewScanner(),
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

// begin cancels any running operation and returns a fresh context plus an end
// function that clears the cancellation state.
func (a *App) begin() (context.Context, func()) {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.gen++
	gen := a.gen
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	a.mu.Unlock()

	return ctx, func() {
		cancel()
		a.mu.Lock()
		if a.gen == gen {
			a.cancel = nil
		}
		a.mu.Unlock()
	}
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
	if opts.BruteForce || opts.PTR || opts.Services {
		discovered = subdomains.Discover(ctx, net.DefaultResolver, req.Domain, subdomains.Options{
			BruteForce: opts.BruteForce,
			PTR:        opts.PTR,
			Sweep24:    opts.Sweep24,
			Services:   opts.Services,
			OnProgress: func(done, total, found int) {
				runtime.EventsEmit(a.ctx, EventScanProgress, ScanProgressEvent{
					Phase: "subdomains", Done: done, Total: total, Found: found,
				})
			},
		}, a.subs)
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
	targets = capTargets(targets, limit)
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

// capTargets truncates targets to limit when limit > 0.
func capTargets(targets []dnscheck.Target, limit int) []dnscheck.Target {
	if limit > 0 && len(targets) > limit {
		return targets[:limit]
	}
	return targets
}

// ScanPorts probes a host for open ports, emitting each open port as it is
// found. Results stream through portscan:open/portscan:progress and finish with
// portscan:done (or portscan:error).
func (a *App) ScanPorts(req PortScanRequest) error {
	ctx, end := a.begin()
	defer end()

	host := strings.TrimSpace(req.Host)
	if host == "" {
		message := "no host to scan"
		runtime.EventsEmit(a.ctx, EventPortError, ErrorEvent{Target: 0, Message: message})
		return errors.New(message)
	}

	ports, err := resolveScanPorts(req)
	if err != nil {
		runtime.EventsEmit(a.ctx, EventPortError, ErrorEvent{Target: 0, Message: err.Error()})
		return err
	}

	var open int64
	_, err = a.ports.Scan(ctx, host, portscan.Options{
		Protocol:    req.Protocol,
		Ports:       ports,
		Concurrency: req.Concurrency,
		Timeout:     time.Duration(req.TimeoutMs) * time.Millisecond,
		Probe:       req.Probe,
		Jitter:      portscan.DefaultJitter,
	}, portscan.Observer{
		OnOpen: func(result portscan.Result) {
			atomic.AddInt64(&open, 1)
			runtime.EventsEmit(a.ctx, EventPortOpen, result)
		},
		OnProgress: func(done, total, openCount int) {
			runtime.EventsEmit(a.ctx, EventPortProgress, PortScanProgressEvent{
				Host: host, Done: done, Total: total, Open: openCount,
			})
		},
	})

	if err != nil && !errors.Is(err, context.Canceled) {
		runtime.EventsEmit(a.ctx, EventPortError, ErrorEvent{Target: 0, Message: err.Error()})
		return err
	}
	runtime.EventsEmit(a.ctx, EventPortDone, PortScanDoneEvent{
		Host: host, Scanned: len(ports), Open: int(atomic.LoadInt64(&open)),
	})
	return nil
}

// resolveScanPorts expands a request into a concrete, validated port list.
func resolveScanPorts(req PortScanRequest) ([]int, error) {
	if strings.TrimSpace(req.PortRange) != "" {
		return portscan.ParsePorts(req.PortRange)
	}
	return portscan.PresetPorts(req.Preset)
}

// Cancel stops the running trace or scan, if any.
func (a *App) Cancel() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
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

// emitGeo resolves a hop IP and emits an EventGeo. Lookups run in the
// background so a slow geolocation service never delays the trace stream. A
// failed lookup is still emitted (with Resolved false) so the UI can stop
// showing the hop as pending.
func (a *App) emitGeo(ctx context.Context, target, hop int, ip string) {
	data, err := a.geo.ResolveOne(ctx, ip)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		data = geolocator.GeoData{}
	}
	runtime.EventsEmit(a.ctx, EventGeo, GeoEvent{Target: target, Hop: hop, Geo: data})
}

// emitTargetGeo resolves the target address and emits an EventTargetGeo so the
// destination can be placed on the map even when the trace never reaches it.
func (a *App) emitTargetGeo(ctx context.Context, target int, ip string) {
	data, err := a.geo.ResolveOne(ctx, ip)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		data = geolocator.GeoData{}
	}
	runtime.EventsEmit(a.ctx, EventTargetGeo, TargetGeoEvent{Target: target, Geo: data})
}

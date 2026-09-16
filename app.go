package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"traceroute/internal/dnscheck"
	"traceroute/internal/geolocator"
	"traceroute/internal/history"
	"traceroute/internal/tracerouter"
)

// Event names emitted to the frontend.
const (
	EventHop         = "trace:hop"
	EventGeo         = "trace:geo"
	EventTarget      = "trace:target"
	EventTargetGeo   = "trace:targetGeo"
	EventDone        = "trace:done"
	EventError       = "trace:error"
	EventScanRecords = "scan:records"
	EventScanTargets = "scan:targets"
	EventScanDone    = "scan:done"
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
	Domain  string `json:"domain"`
	MaxHops int    `json:"maxHops"`
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
}

// App is the Wails application backend.
type App struct {
	ctx    context.Context
	runner *tracerouter.Runner
	geo    *geolocator.Resolver
	hist   *history.Store

	mu     sync.Mutex
	gen    uint64
	cancel context.CancelFunc
}

// NewApp creates the application backend.
func NewApp() *App {
	app := &App{
		runner: tracerouter.NewRunner(),
		geo:    geolocator.NewResolver(),
	}

	store, err := history.Open(history.DefaultPath())
	switch {
	case err != nil:
		log.Printf("history: unavailable: %v", err)
	case store != nil:
		app.hist = store
		log.Printf("history: %s", store.Path())
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

// Scan resolves a domain's DNS records and traces every address found,
// emitting results tagged with a target id so the UI can group and colour them.
func (a *App) Scan(req ScanRequest) error {
	ctx, end := a.begin()
	defer end()

	records := dnscheck.Lookup(ctx, net.DefaultResolver, req.Domain)
	runtime.EventsEmit(a.ctx, EventScanRecords, records)

	targets := dnscheck.Targets(ctx, net.DefaultResolver, req.Domain, records)
	targets = filterUnroutable(targets)
	if len(targets) == 0 {
		message := fmt.Sprintf("no routable address records found for %s", req.Domain)
		runtime.EventsEmit(a.ctx, EventError, ErrorEvent{Target: 0, Message: message})
		return errors.New(message)
	}
	runtime.EventsEmit(a.ctx, EventScanTargets, targets)

	sem := make(chan struct{}, scanConcurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t dnscheck.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			_ = a.runTrace(ctx, t.ID, t.IP, req.MaxHops)
		}(target)
	}
	wg.Wait()

	runtime.EventsEmit(a.ctx, EventScanDone, len(targets))
	return nil
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
		runtime.EventsEmit(a.ctx, EventError, ErrorEvent{Target: target, Message: err.Error()})
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

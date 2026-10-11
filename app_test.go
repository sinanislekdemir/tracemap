package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"traceroute/internal/ipblocks"
	"traceroute/internal/ping"
	"traceroute/internal/portscan"
	"traceroute/internal/subdomains"
	"traceroute/internal/webcrawl"
)

// fakePinger stands in for *ping.Pinger: it returns a preset error per host so
// the ping-first filtering is tested without touching the network.
type fakePinger struct {
	mu    sync.Mutex
	down  map[string]error
	pings []string
}

func (f *fakePinger) Ping(_ context.Context, host string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings = append(f.pings, host)
	return f.down[host]
}

func (f *fakePinger) Close() error { return nil }

func TestPingTargetsFiltersUnreachable(t *testing.T) {
	app := &App{emit: func(string, any) {}}
	pinger := &fakePinger{down: map[string]error{
		"10.0.0.2": ping.ErrTimeout,
		"10.0.0.4": ping.ErrNoIPv4, // cannot verify over ICMP; keep the host
	}}
	targets := []PortScanTarget{
		{Host: "10.0.0.1"}, {Host: "10.0.0.2"}, {Host: "10.0.0.3"}, {Host: "10.0.0.4"},
	}
	got := app.pingTargets(context.Background(), pinger, targets, time.Second)
	want := []string{"10.0.0.1", "10.0.0.3", "10.0.0.4"}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Host != want[i] {
			t.Errorf("target %d = %q, want %q", i, got[i].Host, want[i])
		}
	}
}

func TestHostAliveSemantics(t *testing.T) {
	app := &App{emit: func(string, any) {}}
	cases := []struct {
		err  error
		want bool
	}{
		{nil, true},
		{ping.ErrTimeout, false},
		{ping.ErrNoIPv4, true},
		{ping.ErrUnavailable, true},
		{errors.New("boom"), false},
	}
	for _, c := range cases {
		pinger := &fakePinger{down: map[string]error{"host": c.err}}
		if got := app.hostAlive(context.Background(), pinger, "host", time.Second); got != c.want {
			t.Errorf("hostAlive(err=%v) = %v, want %v", c.err, got, c.want)
		}
	}
	if !app.hostAlive(context.Background(), nil, "host", time.Second) {
		t.Error("a nil pinger (check disabled) should keep the host")
	}
}

func TestScanPortsPingFirstSkipsDeadHosts(t *testing.T) {
	var (
		mu      sync.Mutex
		logged  bool
		done    PortScanDoneEvent
		scanned []string
	)
	app := &App{
		ctx: context.Background(),
		emit: func(name string, payload any) {
			mu.Lock()
			defer mu.Unlock()
			switch e := payload.(type) {
			case PortScanLogEvent:
				logged = true
			case PortScanDoneEvent:
				done = e
			case PortScanProgressEvent:
				scanned = append(scanned, e.Host)
			}
		},
		ports: &portscan.Scanner{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("connection refused")
			},
		},
		newPinger: func() (hostPinger, error) {
			return &fakePinger{down: map[string]error{"10.0.0.2": ping.ErrTimeout}}, nil
		},
	}

	err := app.ScanPorts(PortScanRequest{
		CIDR: "10.0.0.0/30", Preset: "top20", PingFirst: true, Concurrency: 4, TimeoutMs: 200,
	})
	if err != nil {
		t.Fatalf("ScanPorts: %v", err)
	}
	if done.Targets != 1 || done.Skipped != 1 {
		t.Errorf("done = %+v, want Targets=1 Skipped=1", done)
	}
	if len(scanned) != 1 || scanned[0] != "10.0.0.1" {
		t.Errorf("scanned hosts = %v, want [10.0.0.1]", scanned)
	}
	if !logged {
		t.Error("expected a portscan:log event for the skipped host")
	}
}

func TestPingTimeout(t *testing.T) {
	if got := pingTimeout(0); got != portPingTimeout {
		t.Errorf("pingTimeout(0) = %s, want %s", got, portPingTimeout)
	}
	if got := pingTimeout(30 * time.Second); got != portPingTimeout {
		t.Errorf("pingTimeout(30s) = %s, want the %s cap", got, portPingTimeout)
	}
	if got := pingTimeout(300 * time.Millisecond); got != 300*time.Millisecond {
		t.Errorf("pingTimeout(300ms) = %s, want 300ms", got)
	}
}

// TestSubdomainIPsNeverNull guards against emitting a nil IPs slice, which
// JSON-encodes as null and crashes the frontend's ips.length access.
func TestSubdomainIPsNeverNull(t *testing.T) {
	results := crawlSubdomainResults([]webcrawl.Subdomain{
		{Name: "www.example.com"},
		{Name: "", IPs: []string{"1.2.3.4"}},
		{Name: "mail.example.com", IPs: []string{"5.6.7.8"}},
	})
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %#v", len(results), results)
	}

	merged := mergeSubdomainResults(results, []subdomains.Result{
		{Name: "bare.example.com"},
		{Name: "www.example.com", IPs: []string{"9.9.9.9"}},
	})

	for _, result := range merged {
		if result.IPs == nil {
			t.Errorf("%s: IPs is nil, want empty slice", result.Name)
		}
	}

	payload, err := json.Marshal(merged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(payload), `"ips":null`) {
		t.Errorf("payload contains null ips: %s", payload)
	}
}

func TestNormalizePortScanTargets(t *testing.T) {
	tests := []struct {
		name string
		req  PortScanRequest
		want []PortScanTarget
	}{
		{
			name: "falls back to host",
			req:  PortScanRequest{Host: "  example.com "},
			want: []PortScanTarget{{Label: "example.com", Host: "example.com"}},
		},
		{
			name: "trims, dedupes and fills labels",
			req: PortScanRequest{Targets: []PortScanTarget{
				{Label: "web", Host: " 10.0.0.1 "},
				{Label: "", Host: "10.0.0.1"},
				{Label: "db", Host: "10.0.0.2"},
				{Host: "   "},
			}},
			want: []PortScanTarget{
				{Label: "web", Host: "10.0.0.1"},
				{Label: "db", Host: "10.0.0.2"},
			},
		},
		{
			name: "empty request yields nothing",
			req:  PortScanRequest{},
			want: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizePortScanTargets(test.req)
			if len(got) != len(test.want) {
				t.Fatalf("got %d targets, want %d: %#v", len(got), len(test.want), got)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Errorf("target %d = %#v, want %#v", i, got[i], test.want[i])
				}
			}
		})
	}
}

func TestFormatPortScanReport(t *testing.T) {
	report := PortScanReport{
		Target:      "example.com",
		Scope:       "all targets (2)",
		StartedAt:   1_700_000_000_000,
		DurationMs:  12_400,
		Protocol:    "tcp",
		Ports:       "Top 100",
		PortCount:   100,
		Probe:       true,
		PingFirst:   true,
		Concurrency: 64,
		TimeoutMs:   500,
		Scanned:     100,
		Open:        4,
		Targets:     2,
		ResolvedTargets: []PortScanTargetInfo{
			{Label: "web", Host: "10.0.0.1"},
			{Label: "db", Host: "10.0.0.2"},
		},
		Rows: []PortScanRow{
			{Host: "10.0.0.1", Label: "web", Port: 443, Protocol: "tcp", Service: "https", Product: "nginx", TLS: true, Detail: "TLS 1.3"},
			{Host: "10.0.0.1", Label: "web", Port: 80, Protocol: "tcp", Service: "http", Product: "nginx", Banner: "nginx/1.24\nready"},
			{Host: "10.0.0.1", Label: "web", Port: 21, Protocol: "tcp", Service: "ftp", Product: "vsFTPd 3.0.3", Banner: "220 (vsFTPd 3.0.3)", FTPAnonymous: boolPtr(true)},
			{Host: "10.0.0.9", Label: "extra", Port: 22, Protocol: "tcp", Service: "ssh"},
		},
	}

	out := formatPortScanReport(report)

	for _, want := range []string{
		"PORT SCAN REPORT",
		"Target:       example.com",
		"Scope:        all targets (2)",
		"Protocol:     tcp",
		"Ports:        Top 100 (100 ports)",
		"Identify:     enabled",
		"Ping first:   enabled",
		"Pacing:       concurrency 64 · timeout 500ms",
		"web (10.0.0.1)",
		"db (10.0.0.2)",
		"no open ports",
		"80/tcp",
		"443/tcp",
		"nginx",
		"[TLS]",
		"detail: TLS 1.3",
		"banner: nginx/1.24 ready",
		"anonymous FTP: ANONYMOUS LOGIN ALLOWED",
		"10.0.0.9",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}

	// Ports within a host are sorted ascending, and resolved-target order is kept.
	if p80, p443 := strings.Index(out, "80/tcp"), strings.Index(out, "443/tcp"); p80 < 0 || p443 < 0 || p80 > p443 {
		t.Errorf("ports not sorted ascending:\n%s", out)
	}
	if db, extra := strings.Index(out, "db (10.0.0.2)"), strings.Index(out, "10.0.0.9"); db < 0 || extra < 0 || db > extra {
		t.Errorf("resolved target order not preserved / extra host missing:\n%s", out)
	}
}

func TestFormatPortScanReportNoRows(t *testing.T) {
	out := formatPortScanReport(PortScanReport{Target: "host", Scanned: 20})
	if !strings.Contains(out, "No open ports were found.") {
		t.Errorf("expected empty-state line:\n%s", out)
	}
	if !strings.Contains(out, "Scope:        single host") {
		t.Errorf("expected single-host scope:\n%s", out)
	}
}

// boolPtr returns a pointer to v, for the optional tri-state report fields.
func boolPtr(v bool) *bool {
	return &v
}

// TestGeoDBPathDotfileRoundTrip checks that a user-picked database path is
// remembered in a dotfile in the home directory and read back.
func TestGeoDBPathDotfileRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if got := loadGeoLite2Path(); got != "" {
		t.Fatalf("loadGeoLite2Path() = %q before saving, want empty", got)
	}

	saveGeoLite2Path("/opt/GeoIP/GeoLite2-Country.mmdb")
	if got, want := loadGeoLite2Path(), "/opt/GeoIP/GeoLite2-Country.mmdb"; got != want {
		t.Fatalf("loadGeoLite2Path() = %q, want %q", got, want)
	}
	if dir := filepath.Dir(geoLite2PathFile()); dir != home {
		t.Fatalf("dotfile dir = %q, want home %q", dir, home)
	}
}

func TestFormatCountryBlocksReport(t *testing.T) {
	page := ipblocks.Page{
		Matched:   2,
		Addresses: "1.20K",
		Blocks:    []string{"1.0.0.0/24", "2.0.0.0/16"},
	}
	out := formatCountryBlocksReport(CountryBlocksRequest{Country: "us", Family: "ipv4"}, page)

	for _, want := range []string{
		"COUNTRY IP BLOCKS",
		"Country:   US",
		"Family:    IPv4",
		"Blocks:    2",
		"Addresses: 1.20K",
		"1.0.0.0/24",
		"2.0.0.0/16",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

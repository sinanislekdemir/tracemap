package main

import (
	"encoding/json"
	"strings"
	"testing"

	"traceroute/internal/subdomains"
	"traceroute/internal/webcrawl"
)

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
		Concurrency: 64,
		TimeoutMs:   500,
		Scanned:     100,
		Open:        3,
		Targets:     2,
		ResolvedTargets: []PortScanTargetInfo{
			{Label: "web", Host: "10.0.0.1"},
			{Label: "db", Host: "10.0.0.2"},
		},
		Rows: []PortScanRow{
			{Host: "10.0.0.1", Label: "web", Port: 443, Protocol: "tcp", Service: "https", Product: "nginx", TLS: true, Detail: "TLS 1.3"},
			{Host: "10.0.0.1", Label: "web", Port: 80, Protocol: "tcp", Service: "http", Product: "nginx", Banner: "nginx/1.24\nready"},
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

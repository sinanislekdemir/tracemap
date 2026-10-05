package main

import (
	"strings"
	"testing"

	"traceroute/internal/geolocator"
	"traceroute/internal/portscan"
)

func geo(lat, lon float64) *geolocator.GeoData {
	return &geolocator.GeoData{Lat: lat, Lon: lon, Resolved: true}
}

func TestCorrelateDedupesSharedHops(t *testing.T) {
	t1 := &traceState{ID: 0, Label: "a", Hops: []hopData{
		{Hop: 1, IP: "10.0.0.1", Geo: geo(10, 10)},
		{Hop: 2, IP: "10.0.0.2", Geo: geo(20, 20)},
	}}
	t2 := &traceState{ID: 1, Label: "b", Hops: []hopData{
		{Hop: 1, IP: "10.0.0.1", Geo: geo(10, 10)},
		{Hop: 2, IP: "10.0.0.3", Geo: geo(30, 30)},
	}}

	hops := correlate([]*traceState{t1, t2})
	if len(hops) != 3 {
		t.Fatalf("got %d unique hops, want 3", len(hops))
	}
	// First-seen order is preserved.
	order := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, want := range order {
		if hops[i].IP != want {
			t.Errorf("hop %d = %q, want %q", i, hops[i].IP, want)
		}
	}
	if hops[0].Count != 2 || hops[0].Paths != 2 {
		t.Errorf("shared hop count=%d paths=%d, want 2/2", hops[0].Count, hops[0].Paths)
	}
	if hops[1].Count != 1 || hops[1].Paths != 1 {
		t.Errorf("unique hop count=%d paths=%d, want 1/1", hops[1].Count, hops[1].Paths)
	}
}

func TestCorrelateSkipsUnlocated(t *testing.T) {
	tr := &traceState{ID: 0, Label: "a", Hops: []hopData{
		{Hop: 1, IP: "10.0.0.1"},                 // no geo: must be skipped
		{Hop: 2, IP: "10.0.0.2", Geo: geo(0, 0)}, // (0,0) means unlocated
		{Hop: 3, IP: "10.0.0.3", Geo: geo(20, 20)},
	}}
	if hops := correlate([]*traceState{tr}); len(hops) != 1 || hops[0].IP != "10.0.0.3" {
		t.Fatalf("got %#v, want only 10.0.0.3", hops)
	}
}

func TestBuildDisplayHopsAppendsTarget(t *testing.T) {
	tr := &traceState{ID: 0, Label: "a", TargetIP: "10.0.0.9", Hops: []hopData{
		{Hop: 1, IP: "10.0.0.1"},
	}}
	hops := buildDisplayHops(tr)
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(hops))
	}
	last := hops[len(hops)-1]
	if last.IP != "10.0.0.9" || !last.IsTarget {
		t.Errorf("last hop = %#v, want target 10.0.0.9", last)
	}
}

func TestBuildDisplayHopsMarksExistingTarget(t *testing.T) {
	tr := &traceState{ID: 0, Label: "a", TargetIP: "10.0.0.2", Hops: []hopData{
		{Hop: 1, IP: "10.0.0.1"},
		{Hop: 2, IP: "10.0.0.2"},
	}}
	hops := buildDisplayHops(tr)
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(hops))
	}
	if !hops[1].IsTarget || hops[0].IsTarget {
		t.Errorf("target marking wrong: %#v", hops)
	}
}

func TestBuildRouteKeepsEndpoints(t *testing.T) {
	pts := [][2]float64{{0, 0}, {1, 1}, {2, 0}}
	route := buildRoute(pts)
	if len(route) <= len(pts) {
		t.Fatalf("route length %d not longer than input %d", len(route), len(pts))
	}
	if route[0] != pts[0] {
		t.Errorf("route start %v, want %v", route[0], pts[0])
	}
	if last := route[len(route)-1]; last != pts[len(pts)-1] {
		t.Errorf("route end %v, want %v", last, pts[len(pts)-1])
	}
}

func TestVisibleTracesHonoursHidden(t *testing.T) {
	u := &uiApp{
		traces: []*traceState{{ID: 0}, {ID: 1}, {ID: 2}},
		hidden: map[int]bool{1: true},
	}
	got := u.visibleTraces()
	if len(got) != 2 || got[0].ID != 0 || got[1].ID != 2 {
		t.Fatalf("visible = %#v, want IDs 0 and 2", got)
	}
	u.hidden = map[int]bool{}
	if got := u.visibleTraces(); len(got) != 3 {
		t.Fatalf("visible = %d, want all 3", len(got))
	}
}

func TestIPFromHopLabel(t *testing.T) {
	tests := map[string]string{
		"1.2.3.4":           "1.2.3.4",
		"1.2.3.4  (target)": "1.2.3.4",
		" 2001:db8::1 ":     "2001:db8::1",
		"*":                 "",
	}
	for in, want := range tests {
		if got := ipFromHopLabel(in); got != want {
			t.Errorf("ipFromHopLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFamilyFromIndex(t *testing.T) {
	tests := map[int]string{0: "", 1: "ipv4", 2: "ipv6", 9: "", -1: ""}
	for idx, want := range tests {
		if got := familyFromIndex(idx); got != want {
			t.Errorf("familyFromIndex(%d) = %q, want %q", idx, got, want)
		}
	}
}

func TestFTPAnonymousLabel(t *testing.T) {
	allowed, denied := true, false
	tests := []struct {
		name string
		in   *bool
		want string
	}{
		{"unchecked", nil, ""},
		{"allowed", &allowed, "anonymous FTP ALLOWED"},
		{"required", &denied, "anonymous FTP required"},
	}
	for _, tt := range tests {
		if got := ftpAnonymousLabel(tt.in); got != tt.want {
			t.Errorf("%s: ftpAnonymousLabel = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := ftpAnonymousColor(&allowed); got != "#ff6b6b" {
		t.Errorf("allowed colour = %q, want red", got)
	}
	if got := ftpAnonymousColor(&denied); got != "#3ddc97" {
		t.Errorf("denied colour = %q, want green", got)
	}
	if got := ftpAnonymousColor(nil); got != "#3ddc97" {
		t.Errorf("unchecked colour = %q, want green", got)
	}
}

func TestIsHTTPService(t *testing.T) {
	tests := []struct {
		r    portscan.Result
		want bool
	}{
		{portscan.Result{Port: 443, TLS: true}, true},
		{portscan.Result{Port: 80, Service: "http"}, true},
		{portscan.Result{Port: 8443}, true},
		{portscan.Result{Port: 22, Service: "ssh"}, false},
		{portscan.Result{Port: 53, Service: "domain"}, false},
	}
	for _, tt := range tests {
		if got := isHTTPService(tt.r); got != tt.want {
			t.Errorf("isHTTPService(%#v) = %v, want %v", tt.r, got, tt.want)
		}
	}
}

func TestPortCount(t *testing.T) {
	if got := portCount(PortScanRequest{PortRange: "22,80,443-445"}); got != 5 {
		t.Errorf("range count = %d, want 5", got)
	}
	if got := portCount(PortScanRequest{Preset: "top20"}); got != 20 {
		t.Errorf("top20 count = %d, want 20", got)
	}
	if got := portCount(PortScanRequest{PortRange: "bogus"}); got != 0 {
		t.Errorf("invalid range count = %d, want 0", got)
	}
}

func TestReportScopeAndPortsLabel(t *testing.T) {
	d := &portDialog{target: "example.com"}
	if got := d.scopeLabel(PortScanRequest{}); got != "single host" {
		t.Errorf("scope = %q, want single host", got)
	}
	if got := d.scopeLabel(PortScanRequest{Targets: []PortScanTarget{{Host: "a"}, {Host: "b"}}}); got != "all targets (2)" {
		t.Errorf("scope = %q, want all targets (2)", got)
	}
	if got := d.portLabel(PortScanRequest{PortRange: "22,80"}); got != "22,80" {
		t.Errorf("ports = %q, want 22,80", got)
	}
	if got := d.portLabel(PortScanRequest{Preset: "top100"}); got != "top100" {
		t.Errorf("ports = %q, want top100", got)
	}
}

func TestUnmaskRulesSummary(t *testing.T) {
	if got := unmaskRulesSummary(UnmaskRulesInfo{}); got == "" {
		t.Error("empty info should still produce a summary")
	}
	exists := unmaskRulesSummary(UnmaskRulesInfo{Path: "/tmp/rules.json", Exists: true})
	if got := exists; !strings.Contains(got, "ready") || !strings.Contains(got, "/tmp/rules.json") {
		t.Errorf("summary = %q, want ready + path", got)
	}
	missing := unmaskRulesSummary(UnmaskRulesInfo{Path: "/tmp/rules.json"})
	if got := missing; !strings.Contains(got, "not created") {
		t.Errorf("summary = %q, want not created", got)
	}
}

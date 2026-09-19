package origin

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"traceroute/internal/subdomains"
)

// fakeDialer dials a fixed address regardless of the requested one, so tests
// can point direct probes at an httptest server.
type fakeDialer struct {
	addr string
	err  error
}

func (f fakeDialer) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	if f.err != nil {
		return nil, f.err
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, f.addr)
}

// fakeResolver serves scripted DNS answers.
type fakeResolver struct {
	ips  map[string][]string
	mx   map[string][]*net.MX
	txts map[string][]string
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	var out []net.IP
	for _, raw := range f.ips[host] {
		if ip := net.ParseIP(raw); ip != nil {
			out = append(out, ip)
		}
	}
	return out, nil
}

func (f fakeResolver) LookupMX(_ context.Context, host string) ([]*net.MX, error) {
	return f.mx[host], nil
}

func (f fakeResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	return f.txts[host], nil
}

// baselineClient returns a client that dials the test server but presents
// serverName as the TLS name, so it exercises the same code path as a proxied
// baseline fetch.
func baselineClient(server *httptest.Server, serverName string) *http.Client {
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	transport.TLSClientConfig.ServerName = serverName
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func testHandler(extra func(http.ResponseWriter)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if extra != nil {
			extra(w)
		}
		if r.URL.Path == "/favicon.ico" {
			_, _ = w.Write([]byte("icon-bytes"))
			return
		}
		_, _ = w.Write([]byte("hello origin"))
	}
}

func testOptions(server *httptest.Server, resolver Resolver) Options {
	return Options{
		Ports:      []int{443},
		Timeout:    3 * time.Second,
		Resolver:   resolver,
		Dial:       fakeDialer{addr: server.Listener.Addr().String()}.dial,
		HTTPClient: baselineClient(server, "example.com"),
	}
}

func TestDiscoverConfirmed(t *testing.T) {
	server := httptest.NewTLSServer(testHandler(nil))
	defer server.Close()

	resolver := fakeResolver{ips: map[string][]string{"example.com": {"127.0.0.1"}}}
	report := Discover(context.Background(), "example.com", testOptions(server, resolver))

	if len(report.Origins) != 1 {
		t.Fatalf("want 1 origin, got %d", len(report.Origins))
	}
	got := report.Origins[0]
	if got.Verdict != VerdictConfirmed {
		t.Fatalf("want confirmed, got %s (evidence %+v)", got.Verdict, got.Evidence)
	}
	if !got.Evidence.CertMatch || !got.Evidence.FaviconMatch || !got.Evidence.BodyMatch {
		t.Fatalf("want cert+favicon+body match, got %+v", got.Evidence)
	}
	if got.Score < 9 {
		t.Fatalf("want score >= 9, got %d", got.Score)
	}
}

func TestDiscoverProxyHeaders(t *testing.T) {
	server := httptest.NewTLSServer(testHandler(func(w http.ResponseWriter) {
		w.Header().Set("Via", "1.1 edge")
	}))
	defer server.Close()

	resolver := fakeResolver{ips: map[string][]string{"example.com": {"10.0.0.1"}}}
	opts := testOptions(server, resolver)
	opts.Subdomains = []subdomains.Result{{Name: "origin.example.com", IPs: []string{"10.0.0.9"}}}

	report := Discover(context.Background(), "example.com", opts)

	var found *Origin
	for i := range report.Origins {
		if report.Origins[i].IP == "10.0.0.9" {
			found = &report.Origins[i]
		}
	}
	if found == nil {
		t.Fatalf("candidate 10.0.0.9 not probed: %+v", report.Origins)
	}
	if found.Verdict != VerdictProxy {
		t.Fatalf("want proxy, got %s (evidence %+v)", found.Verdict, found.Evidence)
	}
	if len(found.Evidence.ProxyHeaders) == 0 {
		t.Fatal("want proxy headers recorded")
	}
}

func TestFrontAddressExcluded(t *testing.T) {
	base := Baseline{Proxied: true, ProxiedIPs: []string{"10.0.0.1"}}
	opts := withDefaults(Options{})
	result := verifyOne(context.Background(), "example.com", base, Candidate{IP: "10.0.0.1"}, opts)
	if result.Verdict != VerdictProxy {
		t.Fatalf("want proxy for a front address, got %s", result.Verdict)
	}
	if result.Note == "" {
		t.Fatal("want a note explaining the front address")
	}
}

func TestDiscoverDead(t *testing.T) {
	server := httptest.NewTLSServer(testHandler(nil))
	defer server.Close()

	opts := testOptions(server, fakeResolver{ips: map[string][]string{"example.com": {"127.0.0.1"}}})
	opts.Dial = fakeDialer{err: errors.New("connection refused")}.dial

	report := Discover(context.Background(), "example.com", opts)
	if len(report.Origins) != 1 || report.Origins[0].Verdict != VerdictDead {
		t.Fatalf("want one dead origin, got %+v", report.Origins)
	}
}

func TestDiscoverNoCandidates(t *testing.T) {
	report := Discover(context.Background(), "example.com", Options{
		Resolver:   fakeResolver{},
		Dial:       fakeDialer{err: errors.New("no network")}.dial,
		HTTPClient: &http.Client{Transport: errorTransport{}, Timeout: time.Second},
	})
	if len(report.Candidates) != 0 {
		t.Fatalf("want no candidates, got %+v", report.Candidates)
	}
	if len(report.Notes) == 0 {
		t.Fatal("want a note explaining the empty footprint")
	}
}

// errorTransport fails every request, keeping the test offline.
type errorTransport struct{}

func (errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

func TestGatherCandidates(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]string{
			"example.com":        {"1.2.3.4"},
			"origin.example.com": {"5.6.7.8"},
			"mail.example.com":   {"9.9.9.9"},
		},
		mx:   map[string][]*net.MX{"example.com": {{Host: "mail.example.com."}}},
		txts: map[string][]string{"example.com": {"v=spf1 ip4:203.0.113.5/32 ip4:198.51.100.7 -all"}},
	}
	base := Baseline{Cert: CertInfo{SANs: []string{"origin.example.com"}}}
	opts := withDefaults(Options{
		Resolver:   resolver,
		Subdomains: []subdomains.Result{{Name: "www.example.com", IPs: []string{"1.2.3.4"}}},
	})

	candidates := gatherCandidates(context.Background(), "example.com", base, opts)
	byIP := map[string]Candidate{}
	for _, candidate := range candidates {
		byIP[candidate.IP] = candidate
	}

	for _, ip := range []string{"1.2.3.4", "5.6.7.8", "9.9.9.9", "203.0.113.5", "198.51.100.7"} {
		if _, ok := byIP[ip]; !ok {
			t.Fatalf("missing candidate %s (got %+v)", ip, candidates)
		}
	}
	apex := byIP["1.2.3.4"]
	if len(apex.Hostnames) != 2 {
		t.Fatalf("want apex shared by 2 hostnames, got %+v", apex.Hostnames)
	}
	if len(byIP["5.6.7.8"].Sources) != 1 || byIP["5.6.7.8"].Sources[0] != "san" {
		t.Fatalf("want SAN source, got %+v", byIP["5.6.7.8"].Sources)
	}
	if len(byIP["203.0.113.5"].Sources) != 1 || byIP["203.0.113.5"].Sources[0] != "spf" {
		t.Fatalf("want SPF source, got %+v", byIP["203.0.113.5"].Sources)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name      string
		evidence  Evidence
		responded bool
		want      Verdict
	}{
		{"dead", Evidence{}, false, VerdictDead},
		{"confirmed content", Evidence{FaviconMatch: true, BodyMatch: true}, true, VerdictConfirmed},
		{"proxy header wins", Evidence{FaviconMatch: true, BodyMatch: true, ProxyHeaders: []string{"via"}}, true, VerdictProxy},
		{"sni variance wins", Evidence{FaviconMatch: true, BodyMatch: true, SNIVariance: true}, true, VerdictProxy},
		{"favicon only", Evidence{FaviconMatch: true}, true, VerdictLikely},
		{"body only", Evidence{BodyMatch: true}, true, VerdictLikely},
		{"cert only", Evidence{CertMatch: true}, true, VerdictLikely},
		{"weak responder", Evidence{StatusMatch: true}, true, VerdictProxy},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classify(test.evidence, test.responded); got != test.want {
				t.Fatalf("want %s, got %s", test.want, got)
			}
		})
	}
}

func TestCertCovers(t *testing.T) {
	server := httptest.NewTLSServer(testHandler(nil))
	defer server.Close()

	cert := server.Certificate()
	if !certCovers(cert, "example.com") {
		t.Fatal("httptest cert should cover example.com")
	}
	if certCovers(cert, "probe-abc.invalid") {
		t.Fatal("httptest cert should not cover an unrelated name")
	}
}

func TestStripCIDR(t *testing.T) {
	if got := stripCIDR("203.0.113.5/32"); got != "203.0.113.5" {
		t.Fatalf("want 203.0.113.5, got %s", got)
	}
	if got := stripCIDR("2001:db8::1"); got != "2001:db8::1" {
		t.Fatalf("want unchanged IPv6, got %s", got)
	}
}

func TestLoadRulesMissingUsesDefaults(t *testing.T) {
	rules, err := LoadRules(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules.HeaderNames) != len(DefaultRules().HeaderNames) {
		t.Fatalf("want default rules, got %+v", rules)
	}
}

func TestRulesRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	want := Rules{HeaderNames: []string{"X-Test", "x-other"}, HeaderPrefixes: []string{"X-Prefix-"}}
	if err := SaveRules(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadRules(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !contains(got.HeaderNames, "x-test") || !contains(got.HeaderNames, "x-other") {
		t.Fatalf("want lower-cased header names, got %+v", got.HeaderNames)
	}
	if !contains(got.HeaderPrefixes, "x-prefix-") {
		t.Fatalf("want lower-cased prefix, got %+v", got.HeaderPrefixes)
	}
}

func TestProxyHeadersCustomRules(t *testing.T) {
	header := http.Header{}
	header.Set("X-Test", "1")
	header.Set("Via", "1.1 edge")

	got := proxyHeaders(header, Rules{HeaderNames: []string{"x-test"}})
	if !contains(got, "x-test") {
		t.Fatalf("want x-test marker, got %v", got)
	}
	if contains(got, "via") {
		t.Fatalf("via should not match custom rules, got %v", got)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for input, want := range map[string]string{
		"https://Example.com/path?q=1": "example.com",
		"example.com.":                 "example.com",
		"  example.com  ":              "example.com",
	} {
		if got := normalizeDomain(input); got != want {
			t.Fatalf("normalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFormatReport(t *testing.T) {
	report := Report{
		Domain:   "example.com",
		Baseline: Baseline{ProxiedIPs: []string{"1.2.3.4"}, Cert: CertInfo{SHA256: "abcdef0123456789", Issuer: "CA"}},
		Origins: []Origin{
			{IP: "5.6.7.8", Verdict: VerdictConfirmed, Score: 9, Ports: []int{443}, Evidence: Evidence{CertMatch: true, FaviconMatch: true}},
		},
	}
	text := FormatReport(report)
	for _, want := range []string{"example.com", "5.6.7.8", "confirmed", "abcdef0123456789"} {
		if !strings.Contains(text, want) {
			t.Fatalf("report missing %q:\n%s", want, text)
		}
	}
}

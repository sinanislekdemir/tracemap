package subdomains

import (
	"context"
	"net"
	"path/filepath"
	"regexp"
	"testing"
)

type fakeResolver struct {
	ips map[string][]net.IP
	txt map[string][]string
	srv map[string][]*net.SRV
	ptr map[string][]string
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	return f.ips[host], nil
}

func (f fakeResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	return f.txt[host], nil
}

func (f fakeResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return "", f.srv["_"+service+"._"+proto+"."+name], nil
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return f.ptr[addr], nil
}

func fastOpts(opts Options) Options {
	opts.Concurrency = 4
	opts.RatePerSecond = 1000000
	return opts
}

func resultNames(results []Result) []string {
	names := make([]string, 0, len(results))
	for _, result := range results {
		names = append(names, result.Name)
	}
	return names
}

func TestBruteForceFindsNames(t *testing.T) {
	resolver := fakeResolver{ips: map[string][]net.IP{
		"www.example.com":     {net.ParseIP("1.1.1.1")},
		"api.example.com":     {net.ParseIP("2.2.2.2")},
		"missing.example.com": nil,
	}}
	opts := fastOpts(Options{BruteForce: true, Wordlist: []string{"www", "api", "missing"}})

	results := Discover(context.Background(), resolver, "example.com", opts, nil)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(results), results)
	}
	if results[0].Name != "api.example.com" || results[1].Name != "www.example.com" {
		t.Errorf("unexpected results: %+v", resultNames(results))
	}
	if results[0].Source != "brute" {
		t.Errorf("source = %q, want brute", results[0].Source)
	}
}

func TestWildcardFiltering(t *testing.T) {
	resolver := fakeResolver{ips: map[string][]net.IP{
		"tracemap-wc.example.com": {net.ParseIP("9.9.9.9")},
		"fake.example.com":        {net.ParseIP("9.9.9.9")},
		"real.example.com":        {net.ParseIP("1.1.1.1")},
	}}
	opts := fastOpts(Options{
		BruteForce:     true,
		Wordlist:       []string{"fake", "real"},
		wildcardLabels: []string{"tracemap-wc"},
	})

	results := Discover(context.Background(), resolver, "example.com", opts, nil)
	if len(results) != 1 || results[0].Name != "real.example.com" {
		t.Fatalf("wildcard hit was not filtered: %+v", resultNames(results))
	}
}

func TestPTRKeepsOnlyInDomain(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{"example.com": {net.ParseIP("1.1.1.1")}},
		ptr: map[string][]string{
			"1.1.1.1": {"host1.example.com.", "unrelated.net."},
		},
	}
	opts := fastOpts(Options{PTR: true})

	results := Discover(context.Background(), resolver, "example.com", opts, nil)
	if len(results) != 1 || results[0].Name != "host1.example.com" || results[0].Source != "ptr" {
		t.Fatalf("unexpected PTR results: %+v", results)
	}
}

func TestSPFAndDMARC(t *testing.T) {
	resolver := fakeResolver{
		txt: map[string][]string{
			"example.com":        {"v=spf1 include:mail.example.com ip4:1.2.3.0/24 -all"},
			"_dmarc.example.com": {"v=DMARC1; rua=mailto:dmarc@reports.example.com"},
		},
		ips: map[string][]net.IP{
			"mail.example.com":    {net.ParseIP("3.3.3.3")},
			"reports.example.com": {net.ParseIP("5.5.5.5")},
		},
	}
	opts := fastOpts(Options{Services: true})

	results := Discover(context.Background(), resolver, "example.com", opts, nil)
	found := map[string]string{}
	for _, result := range results {
		found[result.Name] = result.Source
	}
	if found["mail.example.com"] != "spf" {
		t.Errorf("SPF host missing: %+v", results)
	}
	if found["reports.example.com"] != "dmarc" {
		t.Errorf("DMARC host missing: %+v", results)
	}
}

func TestSRV(t *testing.T) {
	resolver := fakeResolver{
		srv: map[string][]*net.SRV{
			"_sip._tcp.example.com": {{Target: "sip.example.com."}},
		},
		ips: map[string][]net.IP{"sip.example.com": {net.ParseIP("4.4.4.4")}},
	}
	opts := fastOpts(Options{Services: true})

	results := Discover(context.Background(), resolver, "example.com", opts, nil)
	if len(results) != 1 || results[0].Name != "sip.example.com" || results[0].Source != "srv" {
		t.Fatalf("unexpected SRV results: %+v", results)
	}
}

func TestDeduplicatesAcrossSources(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"example.com":      {net.ParseIP("1.1.1.1")},
			"mail.example.com": {net.ParseIP("2.2.2.2")},
		},
		txt: map[string][]string{"example.com": {"v=spf1 include:mail.example.com -all"}},
		ptr: map[string][]string{"2.2.2.2": {"mail.example.com."}},
	}
	opts := fastOpts(Options{BruteForce: true, Wordlist: []string{"mail"}, PTR: true, Services: true})

	results := Discover(context.Background(), resolver, "example.com", opts, nil)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	if len(results[0].IPs) != 1 || results[0].IPs[0] != "2.2.2.2" {
		t.Errorf("IPs not merged: %+v", results[0])
	}
}

func TestMaxResultsCap(t *testing.T) {
	resolver := fakeResolver{ips: map[string][]net.IP{
		"a.example.com": {net.ParseIP("1.1.1.1")},
		"b.example.com": {net.ParseIP("2.2.2.2")},
		"c.example.com": {net.ParseIP("3.3.3.3")},
	}}
	opts := fastOpts(Options{BruteForce: true, Wordlist: []string{"a", "b", "c"}, MaxResults: 2})

	results := Discover(context.Background(), resolver, "example.com", opts, nil)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := fakeResolver{ips: map[string][]net.IP{"www.example.com": {net.ParseIP("1.1.1.1")}}}
	opts := fastOpts(Options{BruteForce: true, Wordlist: []string{"www"}})

	// Must return promptly without panicking when the context is already done.
	_ = Discover(ctx, resolver, "example.com", opts, nil)
}

func TestWordlist(t *testing.T) {
	if len(Wordlist) < 1000 {
		t.Fatalf("Wordlist has %d entries, want at least 1000", len(Wordlist))
	}
	pattern := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	seen := make(map[string]bool, len(Wordlist))
	for _, word := range Wordlist {
		if !pattern.MatchString(word) {
			t.Errorf("invalid label %q", word)
		}
		if seen[word] {
			t.Errorf("duplicate label %q", word)
		}
		seen[word] = true
	}
}

func TestStoreRoundTrip(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "sub.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	want := []Result{
		{Name: "www.example.com", Source: "brute", IPs: []string{"1.1.1.1", "2606::1"}},
		{Name: "mail.example.com", Source: "ptr", IPs: []string{"2.2.2.2"}},
	}
	if err := store.Save(ctx, "example.com", want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Load(ctx, "example.com")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d: %+v", len(got), len(want), got)
	}
	for i := range got {
		if got[i].Name != want[i].Name || got[i].Source != want[i].Source {
			t.Errorf("result %d = %+v, want %+v", i, got[i], want[i])
		}
		if len(got[i].IPs) != len(want[i].IPs) {
			t.Errorf("result %d IPs = %v, want %v", i, got[i].IPs, want[i].IPs)
		}
	}

	if other, err := store.Load(ctx, "other.com"); err != nil || len(other) != 0 {
		t.Errorf("Load(other) = %v, %v; want empty", other, err)
	}
}

func TestParseSPFHosts(t *testing.T) {
	hosts := parseSPFHosts([]string{"v=spf1 include:_spf.google.com a:mail.example.com mx:mx.example.com redirect=_spf.example.net -all"})
	want := map[string]bool{"_spf.google.com": true, "mail.example.com": true, "mx.example.com": true, "_spf.example.net": true}
	for _, host := range hosts {
		if !want[host] {
			t.Errorf("unexpected SPF host %q", host)
		}
	}
	if len(hosts) != len(want) {
		t.Errorf("got %d SPF hosts, want %d: %v", len(hosts), len(want), hosts)
	}
}

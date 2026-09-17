package dnscheck

import (
	"context"
	"net"
	"testing"
)

type fakeResolver struct {
	ips    map[string][]net.IP
	cnames map[string]string
	mxs    map[string][]*net.MX
	nss    map[string][]*net.NS
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	return f.ips[host], nil
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if cname, ok := f.cnames[host]; ok {
		return cname, nil
	}
	return host + ".", nil
}

func (f fakeResolver) LookupMX(_ context.Context, host string) ([]*net.MX, error) {
	return f.mxs[host], nil
}

func (f fakeResolver) LookupNS(_ context.Context, host string) ([]*net.NS, error) {
	return f.nss[host], nil
}

func TestLookupClassifiesRecords(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"example.com": {net.ParseIP("104.20.23.154"), net.ParseIP("2606:4700::1")},
		},
		cnames: map[string]string{"example.com": "example.com.cdn.cloudflare.net."},
		mxs:    map[string][]*net.MX{"example.com": {{Host: "mail.example.com.", Pref: 10}}},
		nss:    map[string][]*net.NS{"example.com": {{Host: "ns1.example.com."}}},
	}

	records := Lookup(context.Background(), resolver, "example.com")
	want := map[string]string{
		"A":     "104.20.23.154",
		"AAAA":  "2606:4700::1",
		"CNAME": "example.com.cdn.cloudflare.net",
		"MX":    "mail.example.com",
		"NS":    "ns1.example.com",
	}
	for typ, value := range want {
		found := false
		for _, record := range records {
			if record.Type == typ && record.Value == value {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s record %q in %+v", typ, value, records)
		}
	}
}

func TestLookupSkipsSelfCNAME(t *testing.T) {
	resolver := fakeResolver{cnames: map[string]string{"example.com": "example.com."}}
	for _, record := range Lookup(context.Background(), resolver, "example.com") {
		if record.Type == "CNAME" {
			t.Errorf("unexpected CNAME record: %+v", record)
		}
	}
}

func TestTargetsFromAddressRecords(t *testing.T) {
	records := []Record{
		{Type: "A", Name: "example.com", Value: "1.1.1.1"},
		{Type: "A", Name: "example.com", Value: "1.1.1.1"},
		{Type: "AAAA", Name: "example.com", Value: "2606:4700::1"},
		{Type: "CNAME", Name: "example.com", Value: "cdn.example.net"},
	}

	targets := Targets(context.Background(), fakeResolver{}, "example.com", records)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(targets), targets)
	}
	if targets[0].ID != 1 || targets[1].ID != 2 {
		t.Errorf("ids not sequential: %+v", targets)
	}
}

func TestTargetsResolvesMXAndNS(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"mail.example.com": {net.ParseIP("2.2.2.2")},
			"ns1.example.com":  {net.ParseIP("3.3.3.3")},
		},
	}
	records := []Record{
		{Type: "A", Name: "example.com", Value: "1.1.1.1"},
		{Type: "MX", Name: "example.com", Value: "mail.example.com"},
		{Type: "NS", Name: "example.com", Value: "ns1.example.com"},
	}

	targets := Targets(context.Background(), resolver, "example.com", records)
	if len(targets) != 3 {
		t.Fatalf("got %d targets, want 3: %+v", len(targets), targets)
	}
	if targets[1].Kind != "MX" || targets[1].IP != "2.2.2.2" {
		t.Errorf("unexpected MX target: %+v", targets[1])
	}
	if targets[2].Kind != "NS" || targets[2].IP != "3.3.3.3" {
		t.Errorf("unexpected NS target: %+v", targets[2])
	}
}

func TestTargetsCapped(t *testing.T) {
	records := make([]Record, 0, MaxTargets+5)
	for i := 0; i < MaxTargets+5; i++ {
		records = append(records, Record{
			Type:  "A",
			Name:  "example.com",
			Value: net.IPv4(10, 0, byte(i/256), byte(i%256)).String(),
		})
	}

	targets := Targets(context.Background(), fakeResolver{}, "example.com", records)
	if len(targets) != MaxTargets {
		t.Errorf("got %d targets, want %d", len(targets), MaxTargets)
	}
}

func hasRecord(records []Record, typ, value string) bool {
	for _, record := range records {
		if record.Type == typ && record.Value == value {
			return true
		}
	}
	return false
}

func countRecords(records []Record, typ, value string) int {
	count := 0
	for _, record := range records {
		if record.Type == typ && record.Value == value {
			count++
		}
	}
	return count
}

func TestExpandFollowsNameservers(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"example.com":       {net.ParseIP("1.1.1.1")},
			"ns1.example.com":   {net.ParseIP("5.5.5.5")},
			"ns1a.provider.net": {net.ParseIP("6.6.6.6")},
		},
		nss: map[string][]*net.NS{
			"example.com":     {{Host: "ns1.example.com."}},
			"ns1.example.com": {{Host: "ns1a.provider.net."}},
		},
	}

	base := Lookup(context.Background(), resolver, "example.com")
	expanded := Expand(context.Background(), resolver, "example.com", base, 3)

	want := []Record{
		{Type: "A", Value: "1.1.1.1"},
		{Type: "NS", Value: "ns1.example.com"},
		{Type: "A", Value: "5.5.5.5"},
		{Type: "NS", Value: "ns1a.provider.net"},
		{Type: "A", Value: "6.6.6.6"},
	}
	for _, record := range want {
		if !hasRecord(expanded, record.Type, record.Value) {
			t.Errorf("missing %s %q in %+v", record.Type, record.Value, expanded)
		}
	}
}

func TestExpandRespectsDepth(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"example.com":       {net.ParseIP("1.1.1.1")},
			"ns1.example.com":   {net.ParseIP("5.5.5.5")},
			"ns1a.provider.net": {net.ParseIP("6.6.6.6")},
		},
		nss: map[string][]*net.NS{
			"example.com":     {{Host: "ns1.example.com."}},
			"ns1.example.com": {{Host: "ns1a.provider.net."}},
		},
	}

	base := Lookup(context.Background(), resolver, "example.com")
	expanded := Expand(context.Background(), resolver, "example.com", base, 1)

	if !hasRecord(expanded, "A", "5.5.5.5") {
		t.Error("first-level nameserver address was not expanded")
	}
	if hasRecord(expanded, "A", "6.6.6.6") {
		t.Error("expansion went past the depth limit")
	}
}

func TestExpandTerminatesOnLoop(t *testing.T) {
	resolver := fakeResolver{
		nss: map[string][]*net.NS{
			"example.com":     {{Host: "ns1.example.com."}},
			"ns1.example.com": {{Host: "example.com."}},
		},
	}

	base := Lookup(context.Background(), resolver, "example.com")
	expanded := Expand(context.Background(), resolver, "example.com", base, 5)
	if len(expanded) == 0 {
		t.Fatal("expected at least the base records")
	}
}

func TestExpandDeduplicates(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"ns1.example.com": {net.ParseIP("5.5.5.5")},
		},
		nss: map[string][]*net.NS{
			"example.com": {{Host: "ns1.example.com."}},
		},
	}
	records := []Record{
		{Type: "A", Name: "example.com", Value: "5.5.5.5"},
		{Type: "NS", Name: "example.com", Value: "ns1.example.com"},
	}

	expanded := Expand(context.Background(), resolver, "example.com", records, 3)
	if got := countRecords(expanded, "A", "5.5.5.5"); got != 1 {
		t.Errorf("A 5.5.5.5 appears %d times, want 1", got)
	}
}

func TestTargetsUsesRecordName(t *testing.T) {
	records := []Record{{Type: "A", Name: "ns1.example.com", Value: "5.5.5.5"}}
	targets := Targets(context.Background(), fakeResolver{}, "example.com", records)
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1: %+v", len(targets), targets)
	}
	if targets[0].Label != "ns1.example.com" {
		t.Errorf("label = %q, want ns1.example.com", targets[0].Label)
	}
}

const sampleSOA = "ns1.example.com hostmaster.example.com 2018033792 3600 120 1209600 86400"

type fakeSOAResolver struct {
	fakeResolver
	soa Record
}

func (f fakeSOAResolver) LookupSOA(_ context.Context, _ string) (Record, bool) {
	return f.soa, f.soa.Type != ""
}

func TestLookupAllIncludesSOA(t *testing.T) {
	resolver := fakeSOAResolver{
		fakeResolver: fakeResolver{ips: map[string][]net.IP{"example.com": {net.ParseIP("1.1.1.1")}}},
		soa:          Record{Type: "SOA", Name: "example.com", Value: sampleSOA},
	}

	records := LookupAll(context.Background(), resolver, "example.com")
	if !hasRecord(records, "SOA", sampleSOA) {
		t.Errorf("SOA missing from LookupAll result: %+v", records)
	}

	plain := LookupAll(context.Background(), fakeResolver{}, "example.com")
	if hasRecord(plain, "SOA", sampleSOA) {
		t.Error("plain resolver should not produce an SOA record")
	}
}

func TestExpandFollowsSOAMNAME(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"ns1.example.com": {net.ParseIP("5.5.5.5")},
		},
	}
	records := []Record{{Type: "SOA", Name: "example.com", Value: sampleSOA}}

	expanded := Expand(context.Background(), resolver, "example.com", records, 3)
	if !hasRecord(expanded, "A", "5.5.5.5") {
		t.Errorf("SOA MNAME was not expanded: %+v", expanded)
	}
}

func TestTargetsResolvesSOAMNAME(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{"ns1.example.com": {net.ParseIP("5.5.5.5")}},
	}
	records := []Record{{Type: "SOA", Name: "example.com", Value: sampleSOA}}

	targets := Targets(context.Background(), resolver, "example.com", records)
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1: %+v", len(targets), targets)
	}
	if targets[0].Kind != "SOA" || targets[0].IP != "5.5.5.5" {
		t.Errorf("unexpected SOA target: %+v", targets[0])
	}
}

func TestTargetsResolvesSOARNAME(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{
			"ns1.example.com":        {net.ParseIP("5.5.5.5")},
			"hostmaster.example.com": {net.ParseIP("6.6.6.6")},
		},
	}
	records := []Record{{Type: "SOA", Name: "example.com", Value: sampleSOA}}

	targets := Targets(context.Background(), resolver, "example.com", records)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(targets), targets)
	}
	if targets[1].IP != "6.6.6.6" || targets[1].Label != "hostmaster.example.com" {
		t.Errorf("unexpected RNAME target: %+v", targets[1])
	}
}

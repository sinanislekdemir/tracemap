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

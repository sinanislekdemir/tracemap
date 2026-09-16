// Package dnscheck resolves DNS records for a domain and derives the addresses
// worth tracing.
package dnscheck

import (
	"context"
	"net"
	"strings"
)

// Record is a single DNS answer.
type Record struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority int    `json:"priority,omitempty"`
}

// Target is an address to trace, tagged with the record it came from.
type Target struct {
	ID    int    `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
	IP    string `json:"ip"`
}

// MaxTargets caps how many addresses an advanced scan will trace.
const MaxTargets = 12

// Resolver is the subset of net.Resolver used here, so it can be faked in tests.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

// Lookup gathers A, AAAA, CNAME, MX and NS records for domain. Individual
// record failures are ignored so a partial result is still useful.
func Lookup(ctx context.Context, resolver Resolver, domain string) []Record {
	records := make([]Record, 0, 8)
	seen := make(map[string]bool)
	add := func(record Record) {
		key := record.Type + "|" + record.Value
		if seen[key] {
			return
		}
		seen[key] = true
		records = append(records, record)
	}

	if ips, err := resolver.LookupIP(ctx, "ip", domain); err == nil {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				add(Record{Type: "A", Name: domain, Value: v4.String()})
			} else {
				add(Record{Type: "AAAA", Name: domain, Value: ip.String()})
			}
		}
	}

	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil {
		if canonical := strings.TrimSuffix(cname, "."); !strings.EqualFold(canonical, domain) {
			add(Record{Type: "CNAME", Name: domain, Value: canonical})
		}
	}

	if mxs, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			add(Record{Type: "MX", Name: domain, Value: strings.TrimSuffix(mx.Host, "."), Priority: int(mx.Pref)})
		}
	}

	if nss, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			add(Record{Type: "NS", Name: domain, Value: strings.TrimSuffix(ns.Host, ".")})
		}
	}

	return records
}

// Targets derives the addresses to trace: the A/AAAA addresses directly, plus
// the addresses behind MX and NS hostnames. Duplicates are removed and the
// result is capped at MaxTargets.
func Targets(ctx context.Context, resolver Resolver, domain string, records []Record) []Target {
	targets := make([]Target, 0, len(records))
	seen := make(map[string]bool)
	add := func(kind, label, ip string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		targets = append(targets, Target{ID: len(targets) + 1, Kind: kind, Label: label, IP: ip})
	}

	for _, record := range records {
		if record.Type == "A" || record.Type == "AAAA" {
			add(record.Type, domain, record.Value)
		}
	}
	for _, record := range records {
		if record.Type != "MX" && record.Type != "NS" {
			continue
		}
		ips, err := resolver.LookupIP(ctx, "ip", record.Value)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			add(record.Type, record.Value, ip.String())
		}
	}

	if len(targets) > MaxTargets {
		targets = targets[:MaxTargets]
	}
	return targets
}

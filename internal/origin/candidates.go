package origin

import (
	"context"
	"net"
	"sort"
	"strings"

	"traceroute/internal/netutil"
	"traceroute/internal/subdomains"
)

// gatherCandidates mines every address the target's DNS footprint exposes:
// the apex, the reused scan's subdomains, MX hosts, SPF ip literals and the
// certificate SANs observed on the baseline. Everything is local DNS.
func gatherCandidates(ctx context.Context, domain string, base Baseline, opts Options) []Candidate {
	type accumulator struct {
		hostnames map[string]struct{}
		sources   map[string]struct{}
	}
	seen := map[string]*accumulator{}

	add := func(ip, hostname, source string) {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			return
		}
		entry := seen[ip]
		if entry == nil {
			entry = &accumulator{hostnames: map[string]struct{}{}, sources: map[string]struct{}{}}
			seen[ip] = entry
		}
		if hostname != "" {
			entry.hostnames[hostname] = struct{}{}
		}
		if source != "" {
			entry.sources[source] = struct{}{}
		}
	}

	for _, ip := range netutil.ResolveIPs(ctx, opts.Resolver, domain) {
		add(ip, domain, "dns")
	}

	for _, result := range opts.Subdomains {
		for _, ip := range result.IPs {
			add(ip, result.Name, "dns")
		}
	}

	if records, err := opts.Resolver.LookupMX(ctx, domain); err == nil {
		for _, record := range records {
			host := strings.TrimSuffix(record.Host, ".")
			for _, ip := range netutil.ResolveIPs(ctx, opts.Resolver, host) {
				add(ip, host, "mx")
			}
		}
	}

	if txts, err := opts.Resolver.LookupTXT(ctx, domain); err == nil {
		for _, literal := range subdomains.ParseSPFIPs(txts) {
			add(stripCIDR(literal), "", "spf")
		}
	}

	for _, name := range base.Cert.SANs {
		for _, ip := range netutil.ResolveIPs(ctx, opts.Resolver, name) {
			add(ip, name, "san")
		}
	}

	// TODO(phase 3): feed zoneNames(ctx, domain, opts) in here to enumerate
	// names locally (NSEC walk / AXFR) without Certificate Transparency. See
	// zone.go for the deferred implementation notes.

	candidates := make([]Candidate, 0, len(seen))
	for ip, entry := range seen {
		candidates = append(candidates, Candidate{
			IP:        ip,
			Hostnames: netutil.SortedKeys(entry.hostnames),
			Sources:   netutil.SortedKeys(entry.sources),
		})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].IP < candidates[j].IP })
	for _, candidate := range candidates {
		logMessage(opts, "info", "candidate %s ← %s [%s]",
			candidate.IP, joinOr(candidate.Hostnames, "no hostname"), strings.Join(candidate.Sources, ", "))
	}
	return candidates
}

// stripCIDR returns the address part of a CIDR literal, or the input when it
// has no prefix.
func stripCIDR(literal string) string {
	if i := strings.IndexByte(literal, '/'); i >= 0 {
		return literal[:i]
	}
	return literal
}

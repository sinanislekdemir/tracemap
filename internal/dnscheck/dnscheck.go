// Package dnscheck resolves DNS records for a domain and derives the addresses
// worth tracing.
package dnscheck

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"traceroute/internal/netutil"
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

// MaxNSDepth bounds how many levels of nameserver delegation are followed when
// expanding a scan's records.
const MaxNSDepth = 3

// maxNSHosts caps how many nameserver hostnames are expanded, so a hostile or
// pathological zone cannot trigger unbounded lookups.
const maxNSHosts = 64

// Resolver is the subset of net.Resolver used here, so it can be faked in tests.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

// SOAResolver is implemented by resolvers that can fetch SOA records, which
// net.Resolver does not expose. LookupAll uses it when available.
type SOAResolver interface {
	LookupSOA(ctx context.Context, domain string) (Record, bool)
}

// SystemResolver adapts a net.Resolver and adds SOA lookups via a raw DNS query
// to the configured server. It satisfies Resolver.
type SystemResolver struct {
	*net.Resolver
}

// NewSystemResolver wraps r, defaulting to net.DefaultResolver when r is nil.
func NewSystemResolver(r *net.Resolver) SystemResolver {
	if r == nil {
		r = net.DefaultResolver
	}
	return SystemResolver{Resolver: r}
}

// LookupSOA returns the domain's SOA record formatted as a single value
// (MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM), or ok=false when it cannot
// be fetched.
func (s SystemResolver) LookupSOA(ctx context.Context, domain string) (Record, bool) {
	server := s.serverAddress(ctx, domain)
	if server == "" {
		return Record{}, false
	}
	soa, ok := querySOA(ctx, server, domain)
	if !ok {
		return Record{}, false
	}
	return Record{Type: "SOA", Name: domain, Value: formatSOA(soa)}, true
}

// formatSOA renders an SOA answer as a single space-delimited value
// (MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM). The root name is rendered
// as "." rather than an empty string so every field keeps its position when the
// value is split again; an empty field would let the serial shift into the
// RNAME slot and be mistaken for a hostname.
func formatSOA(soa dnsmessage.SOAResource) string {
	return fmt.Sprintf("%s %s %d %d %d %d %d",
		soaName(soa.NS), soaName(soa.MBox),
		soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.MinTTL)
}

// soaName renders a DNS name without its trailing dot, keeping the root (".") as
// a non-empty token so it survives whitespace splitting.
func soaName(name dnsmessage.Name) string {
	trimmed := strings.TrimSuffix(name.String(), ".")
	if trimmed == "" {
		return "."
	}
	return trimmed
}

// serverAddress discovers the configured DNS server by observing the address
// the pure-Go resolver dials.
func (s SystemResolver) serverAddress(ctx context.Context, domain string) string {
	var server string
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if server == "" {
			server = address
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}}
	_, _ = resolver.LookupNS(ctx, domain)
	return server
}

// querySOA sends a single SOA query over UDP and returns the first SOA answer.
func querySOA(ctx context.Context, server, domain string) (dnsmessage.SOAResource, bool) {
	name, err := dnsmessage.NewName(dnsName(domain))
	if err != nil {
		return dnsmessage.SOAResource{}, false
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}},
	}
	packed, err := query.Pack()
	if err != nil {
		return dnsmessage.SOAResource{}, false
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return dnsmessage.SOAResource{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(packed); err != nil {
		return dnsmessage.SOAResource{}, false
	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return dnsmessage.SOAResource{}, false
	}

	var response dnsmessage.Message
	if err := response.Unpack(buffer[:n]); err != nil {
		return dnsmessage.SOAResource{}, false
	}
	for _, answer := range response.Answers {
		if soa, ok := answer.Body.(*dnsmessage.SOAResource); ok {
			return *soa, true
		}
	}
	return dnsmessage.SOAResource{}, false
}

// dnsName returns the absolute (FQDN) form of a domain.
func dnsName(domain string) string {
	if strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

// LookupAll gathers the records for domain, adding the SOA record when the
// resolver supports it. SOA is fetched only for the requested domain, never for
// the nameservers discovered during expansion.
func LookupAll(ctx context.Context, resolver Resolver, domain string) []Record {
	records := Lookup(ctx, resolver, domain)
	soa, ok := resolver.(SOAResolver)
	if !ok {
		return records
	}
	record, ok := soa.LookupSOA(ctx, domain)
	if !ok {
		return records
	}
	for _, existing := range records {
		if existing.Type == "SOA" {
			return records
		}
	}
	return append(records, record)
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

// Expand follows NS records to discover additional addresses. Every
// nameserver hostname is looked up for its own records (A/AAAA/CNAME/MX/NS);
// any addresses found become candidate targets, and NS records of a nameserver
// are followed recursively up to maxDepth (0 uses MaxNSDepth). The original
// records are always included in the result, which is deduplicated by
// type+value. The starting domain and every visited nameserver are tracked so
// delegation loops terminate.
func Expand(ctx context.Context, resolver Resolver, domain string, records []Record, maxDepth int) []Record {
	if maxDepth <= 0 {
		maxDepth = MaxNSDepth
	}

	seenHost := map[string]bool{netutil.NormalizeHost(domain): true}
	seenRecord := make(map[string]bool, len(records))
	out := make([]Record, 0, len(records))
	add := func(record Record) {
		key := record.Type + "|" + record.Value
		if seenRecord[key] {
			return
		}
		seenRecord[key] = true
		out = append(out, record)
	}

	for _, record := range records {
		add(record)
	}

	queue := nsHosts(records)
	expanded := 0
	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		next := make([]string, 0, len(queue))
		for _, host := range queue {
			if host == "" || seenHost[host] {
				continue
			}
			if expanded >= maxNSHosts {
				break
			}
			seenHost[host] = true
			expanded++

			sub := Lookup(ctx, resolver, host)
			for _, record := range sub {
				add(record)
			}
			next = append(next, nsHosts(sub)...)
		}
		queue = next
	}

	return out
}

// nsHosts returns the deduplicated nameserver hostnames from a record set,
// including the primary nameserver named by an SOA record.
func nsHosts(records []Record) []string {
	hosts := make([]string, 0, len(records))
	seen := map[string]bool{}
	for _, record := range records {
		host, ok := recordHost(record)
		if !ok || host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts
}

// recordHost returns the hostname a record points at for the types that name a
// host: NS records and the MNAME (primary nameserver) of an SOA record.
func recordHost(record Record) (string, bool) {
	switch record.Type {
	case "NS":
		return netutil.NormalizeHost(record.Value), true
	case "SOA":
		fields := strings.Fields(record.Value)
		if len(fields) == 0 {
			return "", false
		}
		return netutil.NormalizeHost(fields[0]), true
	default:
		return "", false
	}
}

// soaHosts returns the MNAME (primary nameserver) and RNAME (responsible
// mailbox) hostnames from an SOA record value, deduplicated.
func soaHosts(value string) []string {
	fields := strings.Fields(value)
	if len(fields) > 2 {
		fields = fields[:2]
	}
	hosts := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, field := range fields {
		host := netutil.NormalizeHost(field)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts
}

// Targets derives the addresses to trace: the A/AAAA addresses directly, plus
// the addresses behind MX hostnames and the nameservers named by NS/SOA
// records. Duplicates are removed and the result is capped at MaxTargets.
func Targets(ctx context.Context, resolver Resolver, domain string, records []Record) []Target {
	return netutil.Cap(AllTargets(ctx, resolver, domain, records), MaxTargets)
}

// AllTargets is Targets without the MaxTargets cap, so callers can add further
// candidates before applying their own limit.
func AllTargets(ctx context.Context, resolver Resolver, domain string, records []Record) []Target {
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
			label := record.Name
			if label == "" {
				label = domain
			}
			add(record.Type, label, record.Value)
		}
	}
	resolve := func(kind, host string) {
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return
		}
		for _, ip := range ips {
			add(kind, host, ip.String())
		}
	}
	for _, record := range records {
		switch record.Type {
		case "MX":
			resolve(record.Type, record.Value)
		case "NS":
			if host, ok := recordHost(record); ok {
				resolve(record.Type, host)
			}
		case "SOA":
			// Both the primary nameserver (MNAME) and the responsible mailbox
			// (RNAME) are candidate targets.
			for _, host := range soaHosts(record.Value) {
				resolve(record.Type, host)
			}
		}
	}

	return targets
}

// Package subdomains discovers subdomains of a domain using only local DNS:
// wordlist brute force, reverse DNS (PTR), SPF/TXT parsing and SRV records.
package subdomains

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"traceroute/internal/netutil"
	"traceroute/internal/ratelimit"
)

// Resolver is the subset of net.Resolver used for discovery, so it can be
// faked in tests. net.Resolver satisfies it.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Result is one discovered subdomain.
type Result struct {
	Name   string   `json:"name"`
	Source string   `json:"source"`
	IPs    []string `json:"ips"`
}

// Cache persists discovery results between scans.
type Cache interface {
	Load(ctx context.Context, domain string) ([]Result, error)
	Save(ctx context.Context, domain string, results []Result) error
}

// Options controls discovery. The zero value is usable: sensible defaults are
// filled in by Discover.
type Options struct {
	// BruteForce probes every entry of Wordlist under the domain.
	BruteForce bool
	// PTR reverse-resolves discovered IPs and keeps in-domain names.
	PTR bool
	// Sweep24 also reverse-resolves the whole /24 around each IPv4 found.
	Sweep24 bool
	// Services parses SPF/DMARC TXT records and enumerates common SRV records.
	Services bool

	Concurrency     int
	RatePerSecond   int
	MaxResults      int
	MaxPTRNetblocks int
	Wordlist        []string
	// OnProgress reports progress for one discovery phase ("subdomains" for
	// brute force, "ptr" for reverse DNS, "sweep" for the /24 sweep).
	OnProgress func(phase string, done, total, found int)
	// OnLog reports verbose per-step detail (level is info/ok/warn/error).
	OnLog func(level, message string)

	// wildcardLabels lets tests pin the labels used for wildcard detection.
	wildcardLabels []string
}

// reportProgress invokes OnProgress when the caller subscribed.
func (o Options) reportProgress(phase string, done, total, found int) {
	if o.OnProgress != nil {
		o.OnProgress(phase, done, total, found)
	}
}

// logf invokes OnLog with a formatted message when the caller subscribed.
func (o Options) logf(level, format string, args ...any) {
	if o.OnLog != nil {
		o.OnLog(level, fmt.Sprintf(format, args...))
	}
}

const (
	defaultConcurrency     = 48
	defaultRatePerSecond   = 50
	defaultMaxResults      = 1000
	defaultMaxPTRNetblocks = 4
	maxPTRHostsPerNetblock = 254
	progressEvery          = 25
)

// Discover finds subdomains of domain. When cache is non-nil, cached results
// seed the set and the merged result is written back.
func Discover(ctx context.Context, resolver Resolver, domain string, opts Options, cache Cache) []Result {
	domain = netutil.NormalizeHost(domain)
	opts = withDefaults(opts)

	collector := newCollector(opts.MaxResults)
	if cache != nil {
		if cached, err := cache.Load(ctx, domain); err == nil {
			for _, result := range cached {
				collector.add(result.Name, result.Source, result.IPs)
			}
		}
	}

	// Seed IPs for reverse lookups: everything already known plus the apex.
	seedIPs := collector.ips()
	if ips := netutil.ResolveIPs(ctx, resolver, domain); len(ips) > 0 {
		seedIPs = append(seedIPs, ips...)
	}

	wildcard := detectWildcard(ctx, resolver, domain, opts)

	if opts.BruteForce {
		bruteForce(ctx, resolver, domain, opts, wildcard, collector)
	}
	if opts.Services {
		discoverServices(ctx, resolver, domain, collector)
	}
	if opts.PTR {
		reverseLookup(ctx, resolver, domain, collector, seedIPs, opts)
	}

	results := collector.results()
	if cache != nil {
		_ = cache.Save(ctx, domain, results)
	}
	return results
}

// withDefaults fills unset options with their defaults.
func withDefaults(opts Options) Options {
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.RatePerSecond <= 0 {
		opts.RatePerSecond = defaultRatePerSecond
	}
	if opts.MaxResults <= 0 {
		opts.MaxResults = defaultMaxResults
	}
	if opts.MaxPTRNetblocks <= 0 {
		opts.MaxPTRNetblocks = defaultMaxPTRNetblocks
	}
	if len(opts.Wordlist) == 0 {
		opts.Wordlist = Wordlist
	}
	// A /24 sweep is a reverse-lookup technique; enabling it implies PTR so the
	// option is never silently ignored when PTR is left unchecked.
	if opts.Sweep24 {
		opts.PTR = true
	}
	return opts
}

// collector accumulates unique results, merging IPs seen for the same name.
type collector struct {
	mu     sync.Mutex
	order  []string
	byName map[string]*Result
	max    int
}

func newCollector(max int) *collector {
	return &collector{byName: make(map[string]*Result), max: max}
}

func (c *collector) add(name, source string, ips []string) {
	name = netutil.NormalizeHost(name)
	if name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.byName[name]; ok {
		existing.IPs = netutil.MergeUnique(existing.IPs, ips)
		return
	}
	if len(c.order) >= c.max {
		return
	}
	result := &Result{Name: name, Source: source, IPs: netutil.MergeUnique(nil, ips)}
	c.byName[name] = result
	c.order = append(c.order, name)
}

func (c *collector) ips() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ips []string
	for _, name := range c.order {
		ips = append(ips, c.byName[name].IPs...)
	}
	return ips
}

// count returns how many unique names have been collected so far.
func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.order)
}

func (c *collector) results() []Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Result, 0, len(c.order))
	for _, name := range c.order {
		out = append(out, *c.byName[name])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// detectWildcard probes random labels and returns the set of IPs a wildcard
// zone answers with, so brute-force hits can be filtered.
func detectWildcard(ctx context.Context, resolver Resolver, domain string, opts Options) map[string]bool {
	labels := opts.wildcardLabels
	if len(labels) == 0 {
		labels = randomLabels(3)
	}
	wildcard := make(map[string]bool)
	for _, label := range labels {
		for _, ip := range netutil.ResolveIPs(ctx, resolver, label+"."+domain) {
			wildcard[ip] = true
		}
	}
	return wildcard
}

// bruteForce probes every word under domain.
func bruteForce(ctx context.Context, resolver Resolver, domain string, opts Options, wildcard map[string]bool, c *collector) {
	total := len(opts.Wordlist)
	sem := make(chan struct{}, opts.Concurrency)
	limiter := ratelimit.New(float64(opts.RatePerSecond))
	var wg sync.WaitGroup
	var done, found int64

	for _, word := range opts.Wordlist {
		word = strings.ToLower(strings.TrimSpace(word))
		if word == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := limiter.Wait(ctx); err != nil {
				return
			}
			name := word + "." + domain
			ips := stripWildcard(netutil.ResolveIPs(ctx, resolver, name), wildcard)
			if len(ips) > 0 {
				c.add(name, "brute", ips)
				atomic.AddInt64(&found, 1)
				opts.logf("ok", "brute %s · %s", name, strings.Join(ips, ", "))
			}
			n := atomic.AddInt64(&done, 1)
			if n%progressEvery == 0 || int(n) == total {
				opts.reportProgress("subdomains", int(n), total, int(atomic.LoadInt64(&found)))
			}
		}(word)
	}
	wg.Wait()
}

// discoverServices extracts hostnames from SPF/DMARC TXT records and common SRV
// records.
func discoverServices(ctx context.Context, resolver Resolver, domain string, c *collector) {
	if txts, err := resolver.LookupTXT(ctx, domain); err == nil {
		for _, host := range parseSPFHosts(txts) {
			addResolved(ctx, resolver, domain, "spf", host, c)
		}
	}
	if txts, err := resolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, host := range parseDMARCDomains(txts) {
			addResolved(ctx, resolver, domain, "dmarc", host, c)
		}
	}
	for _, service := range srvServices {
		_, records, err := resolver.LookupSRV(ctx, service.service, service.proto, domain)
		if err != nil {
			continue
		}
		for _, record := range records {
			addResolved(ctx, resolver, domain, "srv", record.Target, c)
		}
	}
}

// addResolved resolves host (if it is a subdomain of domain) and records it.
func addResolved(ctx context.Context, resolver Resolver, domain, source, host string, c *collector) {
	name := netutil.NormalizeHost(host)
	if !netutil.IsStrictSubdomain(name, domain) {
		return
	}
	if ips := netutil.ResolveIPs(ctx, resolver, name); len(ips) > 0 {
		c.add(name, source, ips)
	}
}

// reverseLookup resolves PTR records for known IPs and, when Sweep24 is set,
// for the surrounding /24 of each IPv4. Both phases report progress and log
// every in-domain name they recover.
func reverseLookup(ctx context.Context, resolver Resolver, domain string, c *collector, seedIPs []string, opts Options) {
	ips := netutil.MergeUnique(c.ips(), seedIPs)
	limiter := ratelimit.New(float64(opts.RatePerSecond))

	// Reverse DNS phase: the addresses already known, nothing else.
	ptrTargets := make([]string, 0, len(ips))
	for _, ip := range ips {
		if netutil.IsPublicIP(ip) {
			ptrTargets = append(ptrTargets, ip)
		}
	}
	opts.logf("info", "reverse DNS · %d address(es)", len(ptrTargets))
	opts.reportProgress("ptr", 0, len(ptrTargets), c.count())
	for i, ip := range ptrTargets {
		if err := limiter.Wait(ctx); err != nil {
			return
		}
		for _, name := range addPTR(ctx, resolver, domain, ip, c) {
			opts.logf("ok", "ptr %s → %s", ip, name)
		}
		if done := i + 1; done%progressEvery == 0 || done == len(ptrTargets) {
			opts.reportProgress("ptr", done, len(ptrTargets), c.count())
		}
	}

	if !opts.Sweep24 {
		return
	}

	// /24 sweep phase: every host address in the netblocks around the known
	// IPv4 addresses, bounded by MaxPTRNetblocks.
	seenNet := make(map[string]bool)
	var networks []string
	for _, ip := range ips {
		if len(networks) >= opts.MaxPTRNetblocks {
			break
		}
		network := ipv4Network(ip)
		if network == "" || seenNet[network] {
			continue
		}
		seenNet[network] = true
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		opts.logf("warn", "sweep /24 · no IPv4 netblocks to sweep")
		return
	}

	total := len(networks) * maxPTRHostsPerNetblock
	opts.logf("info", "sweep /24 · %d netblock(s) · %d hosts", len(networks), total)
	opts.reportProgress("sweep", 0, total, c.count())
	done := 0
	for _, network := range networks {
		before := c.count()
		opts.logf("info", "sweeping %s.0/24", network)
		for host := 1; host <= maxPTRHostsPerNetblock; host++ {
			if err := limiter.Wait(ctx); err != nil {
				return
			}
			for _, name := range addPTR(ctx, resolver, domain, network+"."+strconv.Itoa(host), c) {
				opts.logf("ok", "sweep %s.%d → %s", network, host, name)
			}
			done++
			if done%progressEvery == 0 || done == total {
				opts.reportProgress("sweep", done, total, c.count())
			}
		}
		opts.logf("info", "swept %s.0/24 · %d new name(s)", network, c.count()-before)
	}
}

// addPTR reverse-resolves one address, records in-domain names and returns the
// names it added.
func addPTR(ctx context.Context, resolver Resolver, domain, ip string, c *collector) []string {
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil
	}
	var added []string
	for _, name := range names {
		name = netutil.NormalizeHost(name)
		if netutil.IsStrictSubdomain(name, domain) {
			c.add(name, "ptr", []string{ip})
			added = append(added, name)
		}
	}
	return added
}

// parseSPFHosts returns the hostnames referenced by an SPF record.
func parseSPFHosts(txts []string) []string {
	var hosts []string
	for _, txt := range txts {
		lower := strings.ToLower(strings.TrimSpace(txt))
		if !strings.HasPrefix(lower, "v=spf1") && !strings.HasPrefix(lower, "spf2.0") {
			continue
		}
		for _, token := range strings.Fields(txt) {
			token = strings.TrimPrefix(token, "+")
			switch {
			case strings.HasPrefix(token, "include:"):
				hosts = append(hosts, strings.TrimPrefix(token, "include:"))
			case strings.HasPrefix(token, "a:"):
				hosts = append(hosts, strings.TrimPrefix(token, "a:"))
			case strings.HasPrefix(token, "mx:"):
				hosts = append(hosts, strings.TrimPrefix(token, "mx:"))
			case strings.HasPrefix(token, "ptr:"):
				hosts = append(hosts, strings.TrimPrefix(token, "ptr:"))
			case strings.HasPrefix(token, "redirect="):
				hosts = append(hosts, strings.TrimPrefix(token, "redirect="))
			}
		}
	}
	return hosts
}

// ParseSPFIPs returns the IP addresses and CIDR blocks referenced by the ip4:
// and ip6: mechanisms of an SPF record. These often expose infrastructure (and
// sometimes an origin address) that the domain's own A/AAAA records do not.
func ParseSPFIPs(txts []string) []string {
	var ips []string
	for _, txt := range txts {
		lower := strings.ToLower(strings.TrimSpace(txt))
		if !strings.HasPrefix(lower, "v=spf1") && !strings.HasPrefix(lower, "spf2.0") {
			continue
		}
		for _, token := range strings.Fields(txt) {
			token = strings.TrimLeft(token, "+-~?")
			switch {
			case strings.HasPrefix(token, "ip4:"):
				ips = append(ips, strings.TrimPrefix(token, "ip4:"))
			case strings.HasPrefix(token, "ip6:"):
				ips = append(ips, strings.TrimPrefix(token, "ip6:"))
			}
		}
	}
	return ips
}

// parseDMARCDomains returns the domains named in DMARC rua/ruf reports.
func parseDMARCDomains(txts []string) []string {
	var domains []string
	for _, txt := range txts {
		if !strings.Contains(strings.ToLower(txt), "v=dmarc1") {
			continue
		}
		for _, token := range strings.Fields(txt) {
			for _, key := range []string{"rua=", "ruf="} {
				if !strings.HasPrefix(strings.ToLower(token), key) {
					continue
				}
				value := token[len(key):]
				for _, address := range strings.Split(value, ",") {
					address = strings.TrimSpace(strings.TrimPrefix(address, "mailto:"))
					if at := strings.LastIndex(address, "@"); at >= 0 {
						domains = append(domains, address[at+1:])
					}
				}
			}
		}
	}
	return domains
}

// srvService is a service/proto pair probed with LookupSRV.
type srvService struct{ service, proto string }

var srvServices = []srvService{
	{"sip", "tcp"}, {"sip", "tls"}, {"sips", "tcp"},
	{"sipfederationtls", "tcp"}, {"sipinternaltls", "tcp"},
	{"xmpp-server", "tcp"}, {"xmpp-client", "tcp"},
	{"autodiscover", "tcp"},
	{"ldap", "tcp"}, {"ldaps", "tcp"},
	{"kerberos", "tcp"}, {"kerberos", "udp"},
	{"kpasswd", "tcp"}, {"kpasswd", "udp"},
	{"gc", "tcp"},
	{"caldavs", "tcp"}, {"carddavs", "tcp"},
	{"imap", "tcp"}, {"imaps", "tcp"}, {"pop3", "tcp"}, {"pop3s", "tcp"},
	{"smtp", "tcp"}, {"submission", "tcp"},
	{"http", "tcp"}, {"https", "tcp"},
	{"vlmcs", "tcp"},
	{"stun", "tcp"}, {"stun", "udp"},
	{"matrix", "tcp"}, {"wpad", "tcp"}, {"ntp", "udp"},
}

// stripWildcard removes IPs answered by a wildcard zone.
func stripWildcard(ips []string, wildcard map[string]bool) []string {
	if len(wildcard) == 0 || len(ips) == 0 {
		return ips
	}
	out := ips[:0:0]
	for _, ip := range ips {
		if !wildcard[ip] {
			out = append(out, ip)
		}
	}
	return out
}

// ipv4Network returns the /24 network prefix of an IPv4 address, or "".
func ipv4Network(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return v4.String()[:strings.LastIndex(v4.String(), ".")]
}

// randomLabels returns n random DNS labels for wildcard probing.
func randomLabels(n int) []string {
	labels := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			labels = append(labels, "tracemap-wildcard")
			continue
		}
		labels = append(labels, "tracemap-"+hex.EncodeToString(buf))
	}
	return labels
}

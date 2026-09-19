// Package subdomains discovers subdomains of a domain using only local DNS:
// wordlist brute force, reverse DNS (PTR), SPF/TXT parsing and SRV records.
package subdomains

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	OnProgress      func(done, total, found int)

	// wildcardLabels lets tests pin the labels used for wildcard detection.
	wildcardLabels []string
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
	domain = normalize(domain)
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
	if ips := lookupIPs(ctx, resolver, domain); len(ips) > 0 {
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
	name = normalize(name)
	if name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.byName[name]; ok {
		existing.IPs = mergeUnique(existing.IPs, ips)
		return
	}
	if len(c.order) >= c.max {
		return
	}
	result := &Result{Name: name, Source: source, IPs: mergeUnique(nil, ips)}
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
		for _, ip := range lookupIPs(ctx, resolver, label+"."+domain) {
			wildcard[ip] = true
		}
	}
	return wildcard
}

// bruteForce probes every word under domain.
func bruteForce(ctx context.Context, resolver Resolver, domain string, opts Options, wildcard map[string]bool, c *collector) {
	total := len(opts.Wordlist)
	sem := make(chan struct{}, opts.Concurrency)
	limiter := newRateLimiter(opts.RatePerSecond)
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
			if err := limiter.wait(ctx); err != nil {
				return
			}
			name := word + "." + domain
			ips := stripWildcard(lookupIPs(ctx, resolver, name), wildcard)
			if len(ips) > 0 {
				c.add(name, "brute", ips)
				atomic.AddInt64(&found, 1)
			}
			n := atomic.AddInt64(&done, 1)
			if opts.OnProgress != nil && (n%progressEvery == 0 || int(n) == total) {
				opts.OnProgress(int(n), total, int(atomic.LoadInt64(&found)))
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
	name := normalize(host)
	if !isStrictSubdomain(name, domain) {
		return
	}
	if ips := lookupIPs(ctx, resolver, name); len(ips) > 0 {
		c.add(name, source, ips)
	}
}

// reverseLookup resolves PTR records for known IPs and, when Sweep24 is set,
// for the surrounding /24 of each IPv4.
func reverseLookup(ctx context.Context, resolver Resolver, domain string, c *collector, seedIPs []string, opts Options) {
	ips := mergeUnique(c.ips(), seedIPs)
	limiter := newRateLimiter(opts.RatePerSecond)

	for _, ip := range ips {
		if !isPublicIP(ip) {
			continue
		}
		if err := limiter.wait(ctx); err != nil {
			return
		}
		addPTR(ctx, resolver, domain, ip, c)
	}

	if !opts.Sweep24 {
		return
	}
	seenNet := make(map[string]bool)
	networks := 0
	for _, ip := range ips {
		if networks >= opts.MaxPTRNetblocks {
			break
		}
		network := ipv4Network(ip)
		if network == "" || seenNet[network] {
			continue
		}
		seenNet[network] = true
		networks++
		for host := 1; host <= maxPTRHostsPerNetblock; host++ {
			if err := limiter.wait(ctx); err != nil {
				return
			}
			addPTR(ctx, resolver, domain, network+"."+itoa(host), c)
		}
	}
}

// addPTR reverse-resolves one address and records in-domain names.
func addPTR(ctx context.Context, resolver Resolver, domain, ip string, c *collector) {
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return
	}
	for _, name := range names {
		name = normalize(name)
		if isStrictSubdomain(name, domain) {
			c.add(name, "ptr", []string{ip})
		}
	}
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

// lookupIPs resolves host to its IP strings.
func lookupIPs(ctx context.Context, resolver Resolver, host string) []string {
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
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

// normalize lowercases a hostname and strips a trailing root dot.
func normalize(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// isStrictSubdomain reports whether name is a proper subdomain of domain.
func isStrictSubdomain(name, domain string) bool {
	if name == "" || name == domain {
		return false
	}
	return strings.HasSuffix(name, "."+domain)
}

// mergeUnique appends the values of extra that are not already in base.
func mergeUnique(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, value := range base {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, value := range extra {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// isPublicIP reports whether ip is a routable address.
func isPublicIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !(parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() ||
		parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsMulticast())
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

// itoa is a tiny non-allocating integer formatter for small positive ints.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// rateLimiter spaces calls out to at most one per interval.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(perSecond int) *rateLimiter {
	if perSecond <= 0 {
		return &rateLimiter{}
	}
	return &rateLimiter{interval: time.Second / time.Duration(perSecond)}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if r.interval <= 0 {
		return nil
	}
	r.mu.Lock()
	now := time.Now()
	if r.next.Before(now) {
		r.next = now
	}
	delay := r.next.Sub(now)
	r.next = r.next.Add(r.interval)
	r.mu.Unlock()

	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

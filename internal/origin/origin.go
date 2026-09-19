// Package origin discovers the true origin address behind a CDN or reverse
// proxy using only local DNS and direct connections to the target's own
// addresses. It never relies on vendor IP ranges or third-party services: an
// address is treated as the origin when it serves the target's exact content
// directly and shows none of the generic artifacts an intermediary adds.
package origin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"traceroute/internal/geolocator"
	"traceroute/internal/subdomains"
)

// Verdict is the classification of one candidate address.
type Verdict string

const (
	// VerdictConfirmed is an address that serves the target's certificate plus
	// its favicon or body directly, with no intermediary artifacts.
	VerdictConfirmed Verdict = "confirmed"
	// VerdictLikely matches a strong subset of the baseline fingerprints but
	// not enough to be certain.
	VerdictLikely Verdict = "likely"
	// VerdictProxy is an intermediary, or an address that does not serve the
	// target's content directly.
	VerdictProxy Verdict = "proxy"
	// VerdictDead did not answer on any probed port.
	VerdictDead Verdict = "dead"
)

// CertInfo is the fingerprint of a TLS leaf certificate.
type CertInfo struct {
	SHA256   string   `json:"sha256"`
	Subject  string   `json:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	SANs     []string `json:"sans,omitempty"`
	NotAfter int64    `json:"notAfter,omitempty"`
}

// Candidate is one address mined from the target's DNS footprint.
type Candidate struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames,omitempty"`
	Sources   []string `json:"sources"`
}

// Evidence records why a candidate was classified the way it was.
type Evidence struct {
	CertMatch    bool     `json:"certMatch"`
	FaviconMatch bool     `json:"faviconMatch"`
	BodyMatch    bool     `json:"bodyMatch"`
	StatusMatch  bool     `json:"statusMatch"`
	ProxyHeaders []string `json:"proxyHeaders,omitempty"`
	SNIVariance  bool     `json:"sniVariance"`
	FanIn        int      `json:"fanIn"`
}

// Origin is the verified view of one candidate address.
type Origin struct {
	IP       string             `json:"ip"`
	Verdict  Verdict            `json:"verdict"`
	Score    int                `json:"score"`
	Ports    []int              `json:"ports,omitempty"`
	Cert     CertInfo           `json:"cert"`
	Evidence Evidence           `json:"evidence"`
	Geo      geolocator.GeoData `json:"geo"`
	Note     string             `json:"note,omitempty"`
}

// Baseline is the fingerprint captured through the proxy.
type Baseline struct {
	ProxiedIPs []string          `json:"proxiedIps"`
	Proxied    bool              `json:"proxied"`
	Markers    []string          `json:"markers,omitempty"`
	Cert       CertInfo          `json:"cert"`
	Status     int               `json:"status"`
	Headers    map[string]string `json:"headers,omitempty"`
	FaviconSHA string            `json:"faviconSha,omitempty"`
	BodySHA    string            `json:"bodySha,omitempty"`
}

// Report is the full origin-discovery result.
type Report struct {
	Domain     string      `json:"domain"`
	Baseline   Baseline    `json:"baseline"`
	Candidates []Candidate `json:"candidates"`
	Origins    []Origin    `json:"origins"`
	Notes      []string    `json:"notes,omitempty"`
}

// Resolver is the subset of net.Resolver used here, so it can be faked in
// tests. net.Resolver satisfies it.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// DialFunc opens a TCP connection; injectable for tests.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Options configures discovery. The zero value is usable; defaults are filled
// in by Discover.
type Options struct {
	// Ports are probed directly on each candidate. The default covers the
	// common origin ports.
	Ports []int
	// Concurrency bounds how many candidates are probed at once.
	Concurrency int
	// Timeout bounds each connection and request.
	Timeout time.Duration
	// Subdomains reuses the most recent scan's discoveries as candidates.
	Subdomains []subdomains.Result
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// Dial defaults to net.Dialer.DialContext.
	Dial DialFunc
	// HTTPClient is used for the baseline fetch; defaults to a browser-UA client.
	HTTPClient *http.Client
	// Rules are the intermediary markers used to recognise a proxy response.
	// The zero value uses the built-in defaults.
	Rules Rules
	// OnProgress reports phase transitions.
	OnProgress func(phase, message string)
	// OnLog reports verbose per-step detail (level is info/ok/warn/error).
	OnLog func(level, message string)
}

// defaultPorts are the addresses probed on each candidate: standard web ports
// plus common hosting-control ports where an origin is often reachable.
var defaultPorts = []int{443, 80, 8443, 8080, 2083, 2087, 2096, 2082}

const (
	defaultConcurrency = 16
	defaultTimeout     = 8 * time.Second
	maxBodyBytes       = 1 << 20
	maxFaviconBytes    = 256 << 10
)

// Discover mines candidate addresses from the domain's DNS footprint and
// verifies each one directly.
func Discover(ctx context.Context, domain string, opts Options) Report {
	domain = normalizeDomain(domain)
	opts = withDefaults(opts)

	report := Report{Domain: domain}
	logMessage(opts, "info", "unmask %s · %d probe port(s) %v", domain, len(opts.Ports), opts.Ports)
	logMessage(opts, "info", "rules: %d header name(s), %d prefix(es)", len(opts.Rules.HeaderNames), len(opts.Rules.HeaderPrefixes))

	progress(opts, "baseline", "capturing proxied baseline")
	report.Baseline = baseline(ctx, domain, opts)
	logBaseline(opts, report.Baseline)

	progress(opts, "candidates", "mining DNS footprint")
	report.Candidates = gatherCandidates(ctx, domain, report.Baseline, opts)
	logMessage(opts, "info", "%d candidate address(es) mined", len(report.Candidates))
	if len(report.Candidates) == 0 {
		report.Notes = append(report.Notes, "no candidate addresses found in the domain's DNS footprint")
		logMessage(opts, "warn", "no candidate addresses found — run a scan first or the target leaks nothing")
		return report
	}

	progress(opts, "verify", "probing candidates directly")
	report.Origins = verifyCandidates(ctx, domain, report.Baseline, report.Candidates, opts)
	logSummary(opts, report.Origins)

	progress(opts, "done", "origin discovery complete")
	return report
}

// logMessage emits a verbose line when the caller subscribed.
func logMessage(opts Options, level, format string, args ...any) {
	if opts.OnLog != nil {
		opts.OnLog(level, fmt.Sprintf(format, args...))
	}
}

// logSummary reports the verdict tally.
func logSummary(opts Options, origins []Origin) {
	counts := map[Verdict]int{}
	for _, origin := range origins {
		counts[origin.Verdict]++
	}
	logMessage(opts, "ok", "done · %d confirmed · %d likely · %d proxy · %d dead",
		counts[VerdictConfirmed], counts[VerdictLikely], counts[VerdictProxy], counts[VerdictDead])
}

// withDefaults fills unset options with their defaults.
func withDefaults(opts Options) Options {
	if len(opts.Ports) == 0 {
		opts.Ports = append([]int(nil), defaultPorts...)
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.Dial == nil {
		dialer := &net.Dialer{Timeout: opts.Timeout}
		opts.Dial = dialer.DialContext
	}
	if opts.Rules.HeaderNames == nil && opts.Rules.HeaderPrefixes == nil {
		opts.Rules = DefaultRules()
	}
	return opts
}

func progress(opts Options, phase, message string) {
	if opts.OnProgress != nil {
		opts.OnProgress(phase, message)
	}
}

// verifyCandidates probes every candidate with bounded concurrency and returns
// the results ordered by score, highest first.
func verifyCandidates(ctx context.Context, domain string, base Baseline, candidates []Candidate, opts Options) []Origin {
	sem := make(chan struct{}, opts.Concurrency)
	var (
		mu      sync.Mutex
		origins = make([]Origin, 0, len(candidates))
		wg      sync.WaitGroup
	)
	for _, candidate := range candidates {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			result := verifyOne(ctx, domain, base, candidate, opts)
			mu.Lock()
			origins = append(origins, result)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(origins, func(i, j int) bool {
		if origins[i].Score != origins[j].Score {
			return origins[i].Score > origins[j].Score
		}
		return origins[i].IP < origins[j].IP
	})
	return origins
}

// verifyOne probes every configured port on one candidate and keeps the
// strongest match.
func verifyOne(ctx context.Context, domain string, base Baseline, candidate Candidate, opts Options) Origin {
	result := Origin{IP: candidate.IP, Evidence: Evidence{FanIn: len(candidate.Hostnames)}}

	// An address the domain's own DNS returns is the front, not the origin.
	// This is only meaningful when the baseline looked proxied; on a direct
	// (unproxied) target the DNS address is the origin itself.
	if base.Proxied && contains(base.ProxiedIPs, candidate.IP) {
		result.Verdict = VerdictProxy
		result.Note = "is a current DNS answer for the domain (proxy front)"
		logMessage(opts, "warn", "%s skipped · current DNS answer (proxy front)", candidate.IP)
		return result
	}

	logMessage(opts, "info", "probing %s on %v", candidate.IP, opts.Ports)
	var (
		best         endpointResult
		bestEvidence Evidence
		bestScore    = -1
		ports        []int
	)
	for _, port := range opts.Ports {
		if ctx.Err() != nil {
			break
		}
		endpoint := probeEndpoint(ctx, domain, candidate.IP, port, opts)
		if !endpoint.Responded {
			continue
		}
		logMessage(opts, "info", "%s:%d responded · HTTP %d · tls=%t", candidate.IP, port, endpoint.Status, endpoint.HTTPS)
		evidence := compare(base, endpoint, opts.Rules)
		evidence.FanIn = len(candidate.Hostnames)
		switch {
		case score(evidence) > bestScore:
			bestScore = score(evidence)
			best = endpoint
			bestEvidence = evidence
			ports = []int{port}
		case score(evidence) == bestScore && bestScore >= 0:
			ports = append(ports, port)
		}
	}

	if bestScore < 0 {
		result.Verdict = VerdictDead
		logMessage(opts, "warn", "%s → dead · no response on any port", candidate.IP)
		return result
	}

	bestEvidence.SNIVariance = sniVariance(ctx, domain, candidate.IP, base, opts)
	result.Evidence = bestEvidence
	result.Score = score(bestEvidence)
	result.Cert = best.Cert
	result.Ports = ports
	result.Verdict = classify(bestEvidence, true)
	logVerdict(opts, result)
	return result
}

// logVerdict emits the per-candidate verdict with its evidence.
func logVerdict(opts Options, result Origin) {
	level := "info"
	if result.Verdict == VerdictConfirmed || result.Verdict == VerdictLikely {
		level = "ok"
	} else if result.Verdict == VerdictDead {
		level = "warn"
	}
	ev := result.Evidence
	logMessage(opts, level, "%s → %s · score=%d ports=%v cert=%t favicon=%t body=%t proxy=%v sni=%t",
		result.IP, result.Verdict, result.Score, result.Ports,
		ev.CertMatch, ev.FaviconMatch, ev.BodyMatch, ev.ProxyHeaders, ev.SNIVariance)
}

// score weights the fingerprint matches. Content is the reliable signal: a
// proxy passes the body and favicon through unchanged, whereas its certificate
// is the edge's, not the origin's.
func score(evidence Evidence) int {
	n := 0
	if evidence.FaviconMatch {
		n += 4
	}
	if evidence.BodyMatch {
		n += 3
	}
	if evidence.CertMatch {
		n += 2
	}
	if evidence.StatusMatch {
		n++
	}
	return n
}

// classify turns evidence into a verdict. Intermediary artifacts (routing
// headers or a shared-edge SNI behaviour) always win, because they mean the
// response was produced by something other than the origin.
func classify(evidence Evidence, responded bool) Verdict {
	switch {
	case !responded:
		return VerdictDead
	case evidence.SNIVariance || len(evidence.ProxyHeaders) > 0:
		return VerdictProxy
	case evidence.FaviconMatch && evidence.BodyMatch:
		return VerdictConfirmed
	case evidence.FaviconMatch || evidence.BodyMatch:
		return VerdictLikely
	case evidence.CertMatch:
		return VerdictLikely
	default:
		return VerdictProxy
	}
}

// contains reports whether values holds target.
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// normalizeDomain trims a scheme, path and trailing dot from a target.
func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if i := strings.Index(domain, "://"); i >= 0 {
		domain = domain[i+3:]
	}
	if i := strings.IndexAny(domain, "/?#"); i >= 0 {
		domain = domain[:i]
	}
	return strings.TrimSuffix(domain, ".")
}

// FormatReport renders a report as plain text for export.
func FormatReport(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Origin discovery for %s\n", report.Domain)
	fmt.Fprintf(&b, "Generated %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Baseline (through proxy): %s\n", joinOr(report.Baseline.ProxiedIPs, "none"))
	if report.Baseline.Cert.SHA256 != "" {
		fmt.Fprintf(&b, "  certificate: %s (%s)\n", short(report.Baseline.Cert.SHA256), report.Baseline.Cert.Issuer)
	}
	fmt.Fprintf(&b, "\nCandidates: %d\n", len(report.Candidates))
	for _, origin := range report.Origins {
		fmt.Fprintf(&b, "  %-15s %-9s score=%d ports=%v\n", origin.IP, origin.Verdict, origin.Score, origin.Ports)
		ev := origin.Evidence
		fmt.Fprintf(&b, "    cert=%t favicon=%t body=%t status=%t proxyHeaders=%v sniVariance=%t fanIn=%d\n",
			ev.CertMatch, ev.FaviconMatch, ev.BodyMatch, ev.StatusMatch, ev.ProxyHeaders, ev.SNIVariance, ev.FanIn)
		if origin.Note != "" {
			fmt.Fprintf(&b, "    note: %s\n", origin.Note)
		}
	}
	if len(report.Notes) > 0 {
		fmt.Fprintf(&b, "\nNotes:\n")
		for _, note := range report.Notes {
			fmt.Fprintf(&b, "  - %s\n", note)
		}
	}
	return b.String()
}

func joinOr(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return strings.Join(values, ", ")
}

func short(value string) string {
	if len(value) > 16 {
		return value[:16]
	}
	return value
}

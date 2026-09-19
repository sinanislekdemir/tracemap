// Package domaincheck builds a security and reliability report for a domain by
// combining registration data (RDAP, falling back to classic WHOIS), DNS
// records, email authentication and the web/TLS configuration.
package domaincheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Check statuses, from best to worst.
const (
	StatusPass = "pass"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusInfo = "info"
)

// Check categories.
const (
	CategoryRegistration = "registration"
	CategoryDNS          = "dns"
	CategoryEmail        = "email"
	CategoryWeb          = "web"
)

// Check is one item on the report checklist.
type Check struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
}

// DNSRecord is a single DNS answer shown in the report.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Registration is the WHOIS/RDAP summary. Timestamps are Unix milliseconds and
// zero when unknown.
type Registration struct {
	Found        bool     `json:"found"`
	Source       string   `json:"source,omitempty"`
	Domain       string   `json:"domain"`
	Registrar    string   `json:"registrar,omitempty"`
	CreatedAt    int64    `json:"createdAt,omitempty"`
	UpdatedAt    int64    `json:"updatedAt,omitempty"`
	ExpiresAt    int64    `json:"expiresAt,omitempty"`
	AgeDays      int      `json:"ageDays"`
	DaysToExpiry int      `json:"daysToExpiry"`
	Statuses     []string `json:"statuses,omitempty"`
	Nameservers  []string `json:"nameservers,omitempty"`
	Registrant   string   `json:"registrant,omitempty"`
	Country      string   `json:"country,omitempty"`
	DNSSEC       string   `json:"dnssec,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// DNSReport is the DNS and email-authentication picture.
type DNSReport struct {
	Records     []DNSRecord `json:"records"`
	TXT         []string    `json:"txt"`
	SPF         []string    `json:"spf"`
	SPFPolicy   string      `json:"spfPolicy,omitempty"`
	SPFLookups  int         `json:"spfLookups"`
	DMARC       []string    `json:"dmarc"`
	DMARCPolicy string      `json:"dmarcPolicy,omitempty"`
	DMARCRUA    []string    `json:"dmarcRua,omitempty"`
	DKIM        []string    `json:"dkim"`
	MTASTS      []string    `json:"mtaSts,omitempty"`
	TLSRPT      []string    `json:"tlsRpt,omitempty"`
	CAA         []string    `json:"caa"`
	DNSKEY      bool        `json:"dnsKey"`
	DS          bool        `json:"ds"`
	Nameservers []string    `json:"nameservers"`
	MX          []string    `json:"mx"`
	Addresses   []string    `json:"addresses"`
}

// WebReport is the HTTPS/TLS and security-header picture.
type WebReport struct {
	URL            string            `json:"url"`
	HTTPS          bool              `json:"https"`
	HTTPStatus     int               `json:"httpStatus,omitempty"`
	RedirectsHTTPS bool              `json:"redirectsHttps"`
	TLSVersion     string            `json:"tlsVersion,omitempty"`
	CertSubject    string            `json:"certSubject,omitempty"`
	CertIssuer     string            `json:"certIssuer,omitempty"`
	CertNotBefore  int64             `json:"certNotBefore,omitempty"`
	CertNotAfter   int64             `json:"certNotAfter,omitempty"`
	CertDaysLeft   int               `json:"certDaysLeft"`
	Headers        map[string]string `json:"headers,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// Report is the full domain analysis.
type Report struct {
	Domain       string        `json:"domain"`
	AnalyzedAt   int64         `json:"analyzedAt"`
	Score        int           `json:"score"`
	Grade        string        `json:"grade"`
	Checks       []Check       `json:"checks"`
	Registration *Registration `json:"registration,omitempty"`
	DNS          DNSReport     `json:"dns"`
	Web          WebReport     `json:"web"`
}

// ProgressFunc reports a phase transition to the caller.
type ProgressFunc func(phase, message string)

// DialFunc opens a TCP connection; injectable for tests.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Resolver is the subset of net.Resolver used for DNS checks.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// Options configures an Analyzer. Every field is optional; sensible defaults
// are used for the zero value.
type Options struct {
	HTTPClient   *http.Client
	Resolver     Resolver
	Dial         DialFunc
	Raw          RawQueryer
	BootstrapURL string
	Timeout      time.Duration
	WhoisServer  string
}

// Analyzer performs domain analysis. It holds only caches, so it is safe for
// concurrent use.
type Analyzer struct {
	httpClient   *http.Client
	resolver     Resolver
	dial         DialFunc
	raw          RawQueryer
	bootstrapURL string
	timeout      time.Duration
	whoisServer  string

	mu            sync.Mutex
	bootstrap     map[string]string
	bootstrapErr  error
	bootstrapDone bool
	rawServer     string
}

const (
	defaultTimeout      = 8 * time.Second
	defaultBootstrapURL = "https://data.iana.org/rdap/dns.json"
	defaultWhoisServer  = "whois.iana.org:43"
)

// NewAnalyzer creates an Analyzer with production defaults.
func NewAnalyzer() *Analyzer {
	return NewAnalyzerWithOptions(Options{})
}

// NewAnalyzerWithOptions creates an Analyzer, filling defaults for unset
// fields.
func NewAnalyzerWithOptions(opts Options) *Analyzer {
	a := &Analyzer{
		httpClient:   opts.HTTPClient,
		resolver:     opts.Resolver,
		dial:         opts.Dial,
		raw:          opts.Raw,
		bootstrapURL: opts.BootstrapURL,
		timeout:      opts.Timeout,
		whoisServer:  opts.WhoisServer,
	}
	if a.httpClient == nil {
		a.httpClient = &http.Client{Timeout: defaultTimeout}
	}
	if a.resolver == nil {
		a.resolver = net.DefaultResolver
	}
	if a.dial == nil {
		var d net.Dialer
		a.dial = d.DialContext
	}
	if a.bootstrapURL == "" {
		a.bootstrapURL = defaultBootstrapURL
	}
	if a.timeout <= 0 {
		a.timeout = defaultTimeout
	}
	if a.whoisServer == "" {
		a.whoisServer = defaultWhoisServer
	}
	if a.raw == nil {
		a.raw = newSystemQueryer(a.dial, a.timeout)
	}
	return a
}

// Analyze runs the full report for domain. Every phase is best-effort: a
// failure is recorded on the report rather than aborting the whole analysis.
func (a *Analyzer) Analyze(ctx context.Context, domain string, onProgress ProgressFunc) (Report, error) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return Report{}, errors.New("no domain to analyze")
	}

	report := Report{Domain: domain, AnalyzedAt: time.Now().UnixMilli()}

	emitProgress(onProgress, "whois", "querying registration data…")
	registration := a.registration(ctx, domain)
	report.Registration = &registration

	emitProgress(onProgress, "dns", "resolving DNS records…")
	report.DNS = a.dnsReport(ctx, domain)

	emitProgress(onProgress, "web", "checking web and TLS…")
	report.Web = a.webReport(ctx, domain)

	emitProgress(onProgress, "checks", "building checklist…")
	report.Checks = buildChecks(&report)
	report.Score, report.Grade = score(report.Checks)
	return report, nil
}

// registration tries RDAP first and falls back to classic WHOIS.
func (a *Analyzer) registration(ctx context.Context, domain string) Registration {
	if reg, found, err := a.rdapRegistration(ctx, domain); err == nil {
		if found {
			fillDerived(&reg)
			return reg
		}
	}

	reg, found, err := a.whoisRegistration(ctx, domain)
	if err != nil || !found {
		if err != nil {
			reg.Error = err.Error()
		}
		if reg.Domain == "" {
			reg.Domain = domain
		}
		return reg
	}
	fillDerived(&reg)
	return reg
}

// fillDerived computes age and time-to-expiry from the parsed timestamps.
func fillDerived(reg *Registration) {
	now := time.Now()
	if reg.CreatedAt > 0 {
		reg.AgeDays = int(now.Sub(time.UnixMilli(reg.CreatedAt)).Hours() / 24)
	}
	if reg.ExpiresAt > 0 {
		reg.DaysToExpiry = int(time.UnixMilli(reg.ExpiresAt).Sub(now).Hours() / 24)
	}
}

// NormalizeDomain lowercases a domain and strips a scheme, path or trailing
// dot, returning "" when nothing usable remains.
func NormalizeDomain(input string) string {
	domain := strings.TrimSpace(strings.ToLower(input))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if at := strings.IndexAny(domain, "/?#"); at >= 0 {
		domain = domain[:at]
	}
	domain = strings.TrimSuffix(domain, ".")
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	return domain
}

// tld returns the last label of a domain.
func tld(domain string) string {
	if at := strings.LastIndex(domain, "."); at >= 0 {
		return domain[at+1:]
	}
	return domain
}

// parent returns the domain with its first label removed, or "" when none.
func parent(domain string) string {
	if at := strings.Index(domain, "."); at >= 0 {
		return domain[at+1:]
	}
	return ""
}

func emitProgress(fn ProgressFunc, phase, message string) {
	if fn != nil {
		fn(phase, message)
	}
}

// Package httpcheck analyzes a discovered HTTP endpoint: its response headers,
// cookies, caching behaviour and the technology it exposes. It is passive (a
// single browser-like GET) and pure Go, with no external tool.
package httpcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"traceroute/internal/httputil"
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
	CategoryHeaders = "headers"
	CategoryCookies = "cookies"
	CategoryCaching = "caching"
	CategoryTech    = "tech"
	CategoryTLS     = "tls"
)

// Tuning defaults.
const (
	DefaultTimeout = 10 * time.Second
	defaultMaxBody = int64(512 << 10)
	maxRedirects   = 10
)

// Options controls an analysis. The zero value is usable.
type Options struct {
	// Timeout bounds a single request.
	Timeout time.Duration
	// UserAgent is sent with the request; defaults to a browser string.
	UserAgent string
	// Client overrides the HTTP client (used by tests).
	Client *http.Client
	// MaxBodyBytes caps how much of an HTML/text body is read for fingerprinting.
	MaxBodyBytes int64
	// OnLog reports each step, so callers can show what was tried.
	OnLog func(level, message string)
	// OnProgress reports a phase transition.
	OnProgress func(phase, message string)
}

// Header is one response header, tagged with its role.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Kind is one of "security", "info", "cache", "cors", "cookie" or "other".
	Kind string `json:"kind"`
}

// Cookie is one Set-Cookie with its security flags and inferred technology.
type Cookie struct {
	Name     string   `json:"name"`
	Value    string   `json:"value,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path,omitempty"`
	Secure   bool     `json:"secure"`
	HTTPOnly bool     `json:"httpOnly"`
	SameSite string   `json:"sameSite,omitempty"`
	Session  bool     `json:"session"`
	Expires  int64    `json:"expires,omitempty"`
	MaxAge   int      `json:"maxAge,omitempty"`
	Tech     string   `json:"tech,omitempty"`
	Flags    []string `json:"flags,omitempty"`
}

// CacheInfo is the interpreted caching policy of a response.
type CacheInfo struct {
	CacheControl string   `json:"cacheControl,omitempty"`
	Directives   []string `json:"directives,omitempty"`
	Pragma       string   `json:"pragma,omitempty"`
	Expires      string   `json:"expires,omitempty"`
	Age          int      `json:"age"`
	ETag         string   `json:"etag,omitempty"`
	LastModified string   `json:"lastModified,omitempty"`
	Vary         []string `json:"vary,omitempty"`
	Public       bool     `json:"public"`
	Private      bool     `json:"private"`
	NoStore      bool     `json:"noStore"`
	NoCache      bool     `json:"noCache"`
	MaxAge       int      `json:"maxAge"`
	SMaxAge      int      `json:"sMaxAge"`
	Cacheable    bool     `json:"cacheable"`
	Shared       bool     `json:"shared"`
	CDN          string   `json:"cdn,omitempty"`
}

// Tech is one detected technology and the evidence for it.
type Tech struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Evidence string `json:"evidence"`
}

// TLSInfo summarizes the TLS handshake.
type TLSInfo struct {
	Version  string   `json:"version,omitempty"`
	Cipher   string   `json:"cipher,omitempty"`
	ALPN     string   `json:"alpn,omitempty"`
	Subject  string   `json:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	SANs     []string `json:"sans,omitempty"`
	NotAfter int64    `json:"notAfter,omitempty"`
	DaysLeft int      `json:"daysLeft"`
}

// Redirect is one hop in the redirect chain.
type Redirect struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status int    `json:"status"`
}

// Check is one item on the analysis checklist.
type Check struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
}

// Report is the full analysis of one endpoint.
type Report struct {
	URL         string     `json:"url"`
	FinalURL    string     `json:"finalUrl,omitempty"`
	Host        string     `json:"host,omitempty"`
	Status      int        `json:"status"`
	HTTPS       bool       `json:"https"`
	ContentType string     `json:"contentType,omitempty"`
	Server      string     `json:"server,omitempty"`
	Headers     []Header   `json:"headers,omitempty"`
	Checks      []Check    `json:"checks"`
	Cookies     []Cookie   `json:"cookies,omitempty"`
	Caching     CacheInfo  `json:"caching"`
	Tech        []Tech     `json:"tech,omitempty"`
	TLS         *TLSInfo   `json:"tls,omitempty"`
	Redirects   []Redirect `json:"redirects,omitempty"`
	BodySize    int        `json:"bodySize,omitempty"`
	Truncated   bool       `json:"truncated,omitempty"`
	Error       string     `json:"error,omitempty"`
	Score       int        `json:"score"`
	Grade       string     `json:"grade"`
	AnalyzedAt  int64      `json:"analyzedAt"`
}

// Analyze fetches and analyzes one endpoint. When the URL has no scheme it
// tries https first and falls back to http.
func Analyze(ctx context.Context, rawURL string, opts Options) Report {
	opts = withDefaults(opts)
	trimmed := strings.TrimSpace(rawURL)
	now := time.Now().UnixMilli()

	candidates := candidates(trimmed)
	if len(candidates) == 0 {
		return Report{
			URL:        trimmed,
			Error:      "no endpoint to analyze",
			Grade:      "F",
			AnalyzedAt: now,
		}
	}

	var lastErr string
	for _, candidate := range candidates {
		opts.logf("info", "GET %s", candidate)
		report := fetch(ctx, candidate, opts)
		if report.Error == "" {
			report.URL = trimmed
			report.AnalyzedAt = now
			if report.Status != 0 {
				opts.logf("ok", "  → %d %s · %d tech · %d cookie(s)",
					report.Status, report.FinalURL, len(report.Tech), len(report.Cookies))
			}
			return report
		}
		lastErr = report.Error
		opts.logf("warn", "  ✗ %s: %s", candidate, report.Error)
	}

	return Report{URL: trimmed, Error: lastErr, Grade: "F", AnalyzedAt: now}
}

// fetch performs a single GET and builds the full report for it.
func fetch(ctx context.Context, rawurl string, opts Options) Report {
	report := Report{URL: rawurl}

	parsed, err := url.Parse(rawurl)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		report.Error = fmt.Sprintf("unsupported url %q", rawurl)
		return report
	}
	report.Host = parsed.Host
	report.HTTPS = parsed.Scheme == "https"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	var (
		redirects []Redirect
		state     tls.ConnectionState
	)

	client := *opts.Client
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		from := via[len(via)-1]
		status := 0
		if from.Response != nil {
			status = from.Response.StatusCode
		}
		redirects = append(redirects, Redirect{From: from.URL.String(), To: next.URL.String(), Status: status})
		return nil
	}

	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(cs tls.ConnectionState, _ error) { state = cs },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	if err != nil {
		report.Error = err.Error()
		report.Redirects = redirects
		return report
	}
	defer resp.Body.Close()

	report.Redirects = redirects
	report.Status = resp.StatusCode
	report.ContentType = resp.Header.Get("Content-Type")
	report.Server = strings.TrimSpace(resp.Header.Get("Server"))
	report.FinalURL = rawurl
	if resp.Request != nil && resp.Request.URL != nil {
		report.FinalURL = resp.Request.URL.String()
	}
	if resp.TLS != nil {
		report.HTTPS = true
		state = *resp.TLS
	}

	report.Headers = collectHeaders(resp.Header)

	body, truncated := readBody(resp, opts.MaxBodyBytes)
	report.BodySize = len(body)
	report.Truncated = truncated

	report.Cookies = analyzeCookies(resp.Cookies())
	report.Caching = analyzeCaching(resp.Header)
	report.Tech = detectTech(resp.Header, report.Cookies, body, state)
	report.TLS = tlsInfo(state, report.HTTPS)

	buildChecks(&report)
	scoreReport(&report)
	return report
}

// candidates expands an endpoint into the URLs to try, in order.
func candidates(raw string) []string {
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return []string{raw}
	}
	if strings.Contains(raw, "://") {
		return nil
	}
	return []string{"https://" + raw, "http://" + raw}
}

// readBody reads a capped body for fingerprintable content types.
func readBody(resp *http.Response, max int64) ([]byte, bool) {
	if !fingerprintable(resp.Header.Get("Content-Type")) {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, false
	}
	if int64(len(body)) > max {
		return body[:max], true
	}
	return body, false
}

// fingerprintable reports whether a content type is worth reading for
// technology markers.
func fingerprintable(contentType string) bool {
	if contentType == "" {
		return true
	}
	lower := strings.ToLower(contentType)
	for _, marker := range []string{"text/", "html", "xml", "json", "javascript"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// tlsInfo summarizes a completed handshake.
func tlsInfo(state tls.ConnectionState, https bool) *TLSInfo {
	if !https || state.Version == 0 {
		return nil
	}
	info := &TLSInfo{
		Version: tlsVersionName(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
		ALPN:    state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.CommonName
		if info.Subject == "" && len(cert.DNSNames) > 0 {
			info.Subject = cert.DNSNames[0]
		}
		info.Issuer = cert.Issuer.CommonName
		if info.Issuer == "" && len(cert.Issuer.Organization) > 0 {
			info.Issuer = cert.Issuer.Organization[0]
		}
		info.SANs = cert.DNSNames
		info.NotAfter = cert.NotAfter.UnixMilli()
		info.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	}
	return info
}

// tlsVersionName maps a TLS version constant to a label.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return ""
	}
}

// withDefaults fills unset options.
func withDefaults(opts Options) Options {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.UserAgent == "" {
		opts.UserAgent = httputil.BrowserUserAgent
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBody
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Timeout}
	}
	return opts
}

// logf reports a step to the caller.
func (o Options) logf(level, format string, args ...any) {
	if o.OnLog == nil {
		return
	}
	o.OnLog(level, fmt.Sprintf(format, args...))
}

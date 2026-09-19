package origin

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strings"

	"traceroute/internal/httputil"
	"traceroute/internal/netutil"
)

// baseline fetches the target through its normal resolution path (so it hits
// the proxy) and captures the fingerprint to compare candidates against.
func baseline(ctx context.Context, domain string, opts Options) Baseline {
	base := Baseline{Headers: map[string]string{}}
	base.ProxiedIPs = netutil.ResolveIPs(ctx, opts.Resolver, domain)

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return base
	}
	req.Header.Set("User-Agent", httputil.BrowserUserAgent)
	req.Host = domain

	var state tls.ConnectionState
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(cs tls.ConnectionState, _ error) { state = cs },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	if err != nil {
		return base
	}
	defer resp.Body.Close()

	base.Status = resp.StatusCode
	for name := range resp.Header {
		base.Headers[strings.ToLower(name)] = resp.Header.Get(name)
	}
	base.Markers = proxyHeaders(resp.Header, opts.Rules)
	base.Proxied = len(base.Markers) > 0
	if len(state.PeerCertificates) > 0 {
		base.Cert = certInfo(state.PeerCertificates[0])
	}
	if body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes)); err == nil {
		base.BodySHA = sha256Hex(body)
	}
	if favicon, ok := fetchFavicon(ctx, client, "https", domain, 443); ok {
		base.FaviconSHA = sha256Hex(favicon)
	}
	return base
}

// logBaseline emits the captured baseline detail.
func logBaseline(opts Options, base Baseline) {
	if len(base.ProxiedIPs) == 0 {
		logMessage(opts, "warn", "baseline: target did not resolve to any address")
	} else {
		logMessage(opts, "info", "baseline: proxied address(es) %s", strings.Join(base.ProxiedIPs, ", "))
	}
	if base.Status != 0 {
		logMessage(opts, "info", "baseline: https → HTTP %d · favicon=%s body=%s",
			base.Status, hashOrNone(base.FaviconSHA), hashOrNone(base.BodySHA))
	} else {
		logMessage(opts, "warn", "baseline: https fetch failed")
	}
	if base.Cert.SHA256 != "" {
		logMessage(opts, "info", "baseline: cert %s · issuer=%q · sans=%d",
			short(base.Cert.SHA256), base.Cert.Issuer, len(base.Cert.SANs))
	}
	if base.Proxied {
		logMessage(opts, "info", "baseline: intermediary headers present · %s", strings.Join(base.Markers, ", "))
	} else {
		logMessage(opts, "info", "baseline: no known intermediary headers")
	}
}

// hashOrNone renders a short hash or "none".
func hashOrNone(value string) string {
	if value == "" {
		return "none"
	}
	return short(value)
}

// compare scores a direct probe against the baseline.
func compare(base Baseline, endpoint endpointResult, rules Rules) Evidence {
	evidence := Evidence{}
	if !endpoint.Responded {
		return evidence
	}
	evidence.StatusMatch = base.Status != 0 && endpoint.Status == base.Status
	evidence.CertMatch = base.Cert.SHA256 != "" && endpoint.Cert.SHA256 == base.Cert.SHA256
	evidence.FaviconMatch = base.FaviconSHA != "" && endpoint.FaviconSHA == base.FaviconSHA
	evidence.BodyMatch = base.BodySHA != "" && endpoint.BodySHA == base.BodySHA
	evidence.ProxyHeaders = proxyHeaders(endpoint.Headers, rules)
	return evidence
}

// proxyHeaders returns the intermediary headers present on a response, using
// the supplied marker rules.
func proxyHeaders(header http.Header, rules Rules) []string {
	if header == nil {
		return nil
	}
	var found []string
	for _, name := range rules.HeaderNames {
		if header.Get(name) != "" {
			found = append(found, name)
		}
	}
	for name := range header {
		lower := strings.ToLower(name)
		for _, prefix := range rules.HeaderPrefixes {
			if strings.HasPrefix(lower, prefix) {
				found = append(found, lower)
				break
			}
		}
	}
	sort.Strings(found)
	return netutil.Dedupe(found)
}

package domaincheck

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"traceroute/internal/httputil"
)

// securityHeaderNames are the response headers reported and graded.
var securityHeaderNames = []string{
	"strict-transport-security",
	"content-security-policy",
	"x-content-type-options",
	"x-frame-options",
	"referrer-policy",
	"permissions-policy",
}

// webReport probes HTTP and HTTPS, capturing the redirect behaviour, TLS
// certificate and security headers.
func (a *Analyzer) webReport(ctx context.Context, domain string) WebReport {
	report := WebReport{}

	// Plain HTTP probe: observe whether the site redirects to HTTPS.
	noRedirect := *a.httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+"/", nil); err == nil {
		req.Header.Set("User-Agent", httputil.BrowserUserAgent)
		if resp, err := noRedirect.Do(req); err == nil {
			location := strings.ToLower(resp.Header.Get("Location"))
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(location, "https://") {
				report.RedirectsHTTPS = true
			}
			resp.Body.Close()
		}
	}

	// HTTPS probe with TLS handshake capture.
	report.URL = "https://" + domain + "/"
	var state tls.ConnectionState
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(cs tls.ConnectionState, _ error) {
			state = cs
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, report.URL, nil)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	req.Header.Set("User-Agent", httputil.BrowserUserAgent)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		report.Error = err.Error()
	}
	if resp != nil {
		defer resp.Body.Close()
		report.HTTPStatus = resp.StatusCode
		report.Headers = selectHeaders(resp.Header)
		if resp.TLS != nil {
			report.HTTPS = true
			state = *resp.TLS
		}
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		report.CertSubject = cert.Subject.CommonName
		if report.CertSubject == "" && len(cert.DNSNames) > 0 {
			report.CertSubject = cert.DNSNames[0]
		}
		report.CertIssuer = cert.Issuer.CommonName
		if report.CertIssuer == "" && len(cert.Issuer.Organization) > 0 {
			report.CertIssuer = cert.Issuer.Organization[0]
		}
		report.CertNotBefore = cert.NotBefore.UnixMilli()
		report.CertNotAfter = cert.NotAfter.UnixMilli()
		report.CertDaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
		report.TLSVersion = tlsVersionName(state.Version)
	}
	return report
}

// selectHeaders keeps the security-relevant response headers.
func selectHeaders(header http.Header) map[string]string {
	out := make(map[string]string)
	for _, name := range securityHeaderNames {
		if value := header.Get(name); value != "" {
			out[name] = value
		}
	}
	if server := header.Get("Server"); server != "" {
		out["server"] = server
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

package httpcheck

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// securityHeaderNames are the response headers graded for security.
var securityHeaderNames = []string{
	"strict-transport-security",
	"content-security-policy",
	"content-security-policy-report-only",
	"x-content-type-options",
	"x-frame-options",
	"referrer-policy",
	"permissions-policy",
	"cross-origin-opener-policy",
	"cross-origin-embedder-policy",
	"cross-origin-resource-policy",
}

// infoLeakHeaderNames are the response headers known to disclose the stack.
var infoLeakHeaderNames = []string{
	"server",
	"x-powered-by",
	"x-aspnet-version",
	"x-aspnetmvc-version",
	"x-generator",
	"x-runtime",
	"x-debug",
	"x-varnish",
	"x-backend-server",
	"x-drupal-cache",
	"x-drupal-dynamic-cache",
	"x-served-by",
	"x-cache",
}

// collectHeaders returns every response header tagged with its role, with the
// security and information-leak headers listed first.
func collectHeaders(header http.Header) []Header {
	out := make([]Header, 0, len(header))
	seen := make(map[string]bool)

	appendNamed := func(names []string, kind string) {
		for _, name := range names {
			if seen[name] {
				continue
			}
			if value := header.Get(name); value != "" {
				out = append(out, Header{Name: name, Value: value, Kind: kind})
				seen[name] = true
			}
		}
	}
	appendNamed(securityHeaderNames, "security")
	appendNamed(infoLeakHeaderNames, "info")

	names := make([]string, 0, len(header))
	for name := range header {
		lower := strings.ToLower(name)
		if seen[lower] {
			continue
		}
		names = append(names, lower)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, Header{Name: name, Value: header.Get(name), Kind: classifyHeader(name)})
	}
	return out
}

// classifyHeader labels a header by role.
func classifyHeader(name string) string {
	switch {
	case name == "set-cookie":
		return "cookie"
	case strings.HasPrefix(name, "cache-control"), name == "pragma", name == "expires",
		name == "age", name == "etag", name == "last-modified", name == "vary",
		strings.HasPrefix(name, "x-cache"), name == "cf-cache-status",
		name == "surrogate-control", name == "x-served-by", name == "x-vercel-cache":
		return "cache"
	case strings.HasPrefix(name, "access-control-"):
		return "cors"
	case strings.HasPrefix(name, "cf-"), strings.HasPrefix(name, "x-amz-"),
		strings.HasPrefix(name, "x-akamai-"), strings.HasPrefix(name, "x-azure-"):
		return "cdn"
	default:
		return "other"
	}
}

// buildHeaderChecks grades the security headers and flags information leaks.
func buildHeaderChecks(report *Report, add func(id, category, title, status, detail string)) {
	headers := headerMap(report)

	if report.HTTPS {
		hsts := headers["strict-transport-security"]
		switch {
		case hsts == "":
			add("hdr-hsts", CategoryHeaders, "HSTS", StatusFail,
				"No Strict-Transport-Security header: clients can be downgraded to plain HTTP.")
		case hstsMaxAge(hsts) >= 15552000:
			add("hdr-hsts", CategoryHeaders, "HSTS", StatusPass,
				"Strict-Transport-Security present with max-age ≥ 180 days.")
		default:
			add("hdr-hsts", CategoryHeaders, "HSTS", StatusWarn,
				"Strict-Transport-Security present but max-age is short: "+hsts)
		}
	}

	switch csp := headers["content-security-policy"]; {
	case csp == "":
		add("hdr-csp", CategoryHeaders, "Content-Security-Policy", StatusWarn,
			"No Content-Security-Policy: no defence against injected scripts.")
	case strings.Contains(strings.ToLower(csp), "unsafe-inline"):
		add("hdr-csp", CategoryHeaders, "Content-Security-Policy", StatusWarn,
			"CSP allows unsafe-inline, weakening XSS protection.")
	default:
		add("hdr-csp", CategoryHeaders, "Content-Security-Policy", StatusPass,
			"A Content-Security-Policy is set.")
	}

	if value := headers["x-content-type-options"]; strings.EqualFold(strings.TrimSpace(value), "nosniff") {
		add("hdr-nosniff", CategoryHeaders, "X-Content-Type-Options", StatusPass, "nosniff is set.")
	} else if value == "" {
		add("hdr-nosniff", CategoryHeaders, "X-Content-Type-Options", StatusWarn,
			"Missing X-Content-Type-Options: nosniff (MIME sniffing risk).")
	} else {
		add("hdr-nosniff", CategoryHeaders, "X-Content-Type-Options", StatusWarn,
			"X-Content-Type-Options is not nosniff: "+value)
	}

	frame := headers["x-frame-options"]
	cspFrame := strings.Contains(strings.ToLower(headers["content-security-policy"]), "frame-ancestors")
	switch {
	case frame != "" || cspFrame:
		add("hdr-frame", CategoryHeaders, "Clickjacking protection", StatusPass,
			"Framing is restricted by X-Frame-Options or CSP frame-ancestors.")
	default:
		add("hdr-frame", CategoryHeaders, "Clickjacking protection", StatusWarn,
			"No X-Frame-Options or CSP frame-ancestors: the page may be framed.")
	}

	if headers["referrer-policy"] != "" {
		add("hdr-referrer", CategoryHeaders, "Referrer-Policy", StatusPass, "Referrer-Policy is set.")
	} else {
		add("hdr-referrer", CategoryHeaders, "Referrer-Policy", StatusInfo, "No Referrer-Policy header.")
	}

	if headers["permissions-policy"] != "" {
		add("hdr-permissions", CategoryHeaders, "Permissions-Policy", StatusPass, "Permissions-Policy is set.")
	} else {
		add("hdr-permissions", CategoryHeaders, "Permissions-Policy", StatusInfo, "No Permissions-Policy header.")
	}

	if value := headers["server"]; value != "" && looksVersioned(value) {
		add("hdr-server-leak", CategoryHeaders, "Server banner", StatusWarn,
			"Server header discloses the product/version: "+value)
	}
	for _, name := range []string{"x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime"} {
		if value := headers[name]; value != "" {
			add("hdr-leak-"+name, CategoryHeaders, "Technology disclosure", StatusWarn,
				name+": "+value)
		}
	}
	if value := headers["x-debug"]; value != "" {
		add("hdr-debug", CategoryHeaders, "Debug header", StatusWarn, "x-debug present: "+value)
	}

	origin := headers["access-control-allow-origin"]
	credentials := strings.EqualFold(strings.TrimSpace(headers["access-control-allow-credentials"]), "true")
	switch {
	case origin == "*" && credentials:
		add("hdr-cors", CategoryHeaders, "CORS", StatusFail,
			"Access-Control-Allow-Origin: * together with credentials is an unsafe combination.")
	case origin == "*":
		add("hdr-cors", CategoryHeaders, "CORS", StatusInfo,
			"Access-Control-Allow-Origin: * — any origin may read the response.")
	case origin != "":
		add("hdr-cors", CategoryHeaders, "CORS", StatusInfo, "Access-Control-Allow-Origin: "+origin)
	}
}

// headerMap lower-cases the report headers for lookup.
func headerMap(report *Report) map[string]string {
	out := make(map[string]string, len(report.Headers))
	for _, header := range report.Headers {
		out[header.Name] = header.Value
	}
	return out
}

// hstsMaxAge extracts max-age from an HSTS header, or 0.
func hstsMaxAge(value string) int {
	for _, part := range strings.Split(value, ";") {
		name, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		if seconds, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			return seconds
		}
	}
	return 0
}

// looksVersioned reports whether a banner string carries a version-like token.
func looksVersioned(value string) bool {
	for _, r := range value {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	lower := strings.ToLower(value)
	for _, product := range serverProducts {
		if strings.Contains(lower, product) {
			return true
		}
	}
	return false
}

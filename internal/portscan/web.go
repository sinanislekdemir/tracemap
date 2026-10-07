package portscan

import (
	"net"
	"strconv"
	"strings"
)

// WebScheme reports "http" or "https" when the open port's service is a web
// (HTTP) service, and "" otherwise. Service names such as http, https,
// http-alt, https-alt, http-proxy and dev-http all qualify. A successful TLS
// probe, or an "https"-style name, selects https.
func (r Result) WebScheme() string {
	service := strings.ToLower(strings.TrimSpace(r.Service))
	if !strings.Contains(service, "http") {
		return ""
	}
	if r.TLS || strings.HasPrefix(service, "https") {
		return "https"
	}
	return "http"
}

// WebURL returns the browser URL for an open port whose service is a web
// service, and ok=false for anything else. host is the scanned address; IPv6
// literals are bracketed.
func (r Result) WebURL(host string) (string, bool) {
	scheme := r.WebScheme()
	if scheme == "" {
		return "", false
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(r.Port)) + "/", true
}

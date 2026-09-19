package origin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"
)

// browserUA is sent on web probes so sites answer as they would to a browser.
const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

// plainPorts are probed over plain HTTP; every other probed port uses TLS.
var plainPorts = map[int]bool{80: true, 8080: true, 2082: true}

// endpointResult is what a single direct probe captured.
type endpointResult struct {
	Responded  bool
	HTTPS      bool
	Status     int
	Headers    http.Header
	Cert       CertInfo
	BodySHA    string
	FaviconSHA string
}

// probeEndpoint connects directly to ip:port (SNI/Host pinned to domain) and
// captures the response fingerprint.
func probeEndpoint(ctx context.Context, domain, ip string, port int, opts Options) endpointResult {
	scheme := "https"
	if plainPorts[port] {
		scheme = "http"
	}
	client := directClient(ip, domain, opts)
	url := fmt.Sprintf("%s://%s/", scheme, hostForURL(domain, port))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return endpointResult{}
	}
	req.Header.Set("User-Agent", browserUA)
	req.Host = hostForURL(domain, port)

	var state tls.ConnectionState
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(cs tls.ConnectionState, _ error) { state = cs },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	if err != nil {
		return endpointResult{}
	}
	defer resp.Body.Close()

	result := endpointResult{
		Responded: true,
		HTTPS:     scheme == "https",
		Status:    resp.StatusCode,
		Headers:   resp.Header,
	}
	if len(state.PeerCertificates) > 0 {
		result.Cert = certInfo(state.PeerCertificates[0])
	}
	if body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes)); err == nil {
		result.BodySHA = sha256Hex(body)
	}
	if favicon, ok := fetchFavicon(ctx, client, scheme, domain, port); ok {
		result.FaviconSHA = sha256Hex(favicon)
	}
	return result
}

// directClient builds an HTTP client that always dials ip but presents domain
// as the SNI and Host. Certificate verification is skipped on purpose: the
// origin is identified by fingerprint comparison, not by trust.
func directClient(ip, domain string, opts Options) *http.Client {
	dial := opts.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: opts.Timeout}
		dial = dialer.DialContext
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				port = "443"
			}
			return dial(ctx, network, net.JoinHostPort(ip, port))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true, //nolint:gosec // fingerprint comparison, not trust
		},
		TLSHandshakeTimeout: opts.Timeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{Transport: transport, Timeout: opts.Timeout}
}

// fetchFavicon fetches /favicon.ico from the same endpoint.
func fetchFavicon(ctx context.Context, client *http.Client, scheme, domain string, port int) ([]byte, bool) {
	url := fmt.Sprintf("%s://%s/favicon.ico", scheme, hostForURL(domain, port))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", browserUA)
	req.Host = hostForURL(domain, port)

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFaviconBytes))
	if err != nil || len(body) == 0 {
		return nil, false
	}
	return body, true
}

// sniVariance reports whether ip completes a TLS handshake for a name it was
// never asked to serve and answers with a certificate that does not cover the
// target. A shared edge answers any SNI with unrelated or wildcard material; a
// dedicated origin either fails or presents the target's own certificate. It is
// a supporting signal, never decisive on its own.
func sniVariance(ctx context.Context, domain, ip string, base Baseline, opts Options) bool {
	dial := opts.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: opts.Timeout}
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	config := &tls.Config{
		ServerName:         randomLabel() + ".invalid",
		InsecureSkipVerify: true, //nolint:gosec // behaviour probe only
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return false
	}
	cert := state.PeerCertificates[0]
	if base.Cert.SHA256 != "" && sha256Hex(cert.Raw) == base.Cert.SHA256 {
		return false
	}
	return !certCovers(cert, domain)
}

// certCovers reports whether cert is valid for domain (exact or wildcard).
func certCovers(cert *x509.Certificate, domain string) bool {
	domain = strings.ToLower(domain)
	names := cert.DNSNames
	if len(names) == 0 && cert.Subject.CommonName != "" {
		names = []string{cert.Subject.CommonName}
	}
	for _, name := range names {
		name = strings.ToLower(name)
		if name == domain {
			return true
		}
		if strings.HasPrefix(name, "*.") && strings.Count(domain, ".") == strings.Count(name, ".") {
			if strings.HasSuffix(domain, name[1:]) {
				return true
			}
		}
	}
	return false
}

// certInfo fingerprints a leaf certificate.
func certInfo(cert *x509.Certificate) CertInfo {
	return CertInfo{
		SHA256:   sha256Hex(cert.Raw),
		Subject:  cert.Subject.CommonName,
		Issuer:   cert.Issuer.CommonName,
		SANs:     append([]string(nil), cert.DNSNames...),
		NotAfter: cert.NotAfter.UnixMilli(),
	}
}

// hostForURL renders domain:port, omitting the default web ports.
func hostForURL(domain string, port int) string {
	if port == 443 || port == 80 {
		return domain
	}
	return net.JoinHostPort(domain, strconv.Itoa(port))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func randomLabel() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "probe"
	}
	return "probe-" + hex.EncodeToString(buffer)
}

package portscan

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"
)

// Probe tuning. Probes are deliberately short and read-bounded so a scan stays
// quick and a chatty service cannot make it hang.
const (
	probeTimeout = 700 * time.Millisecond
	bannerMax    = 512
	httpMax      = 4096
	bannerLimit  = 200
)

// tlsPorts are ports where a TLS handshake is the expected first exchange.
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 990: true, 993: true, 995: true,
	8443: true, 9443: true, 4443: true, 6443: true,
}

// httpPorts are ports where a plain HTTP request is the expected first exchange.
var httpPorts = map[int]bool{
	80: true, 3000: true, 5000: true, 5601: true, 8000: true, 8008: true,
	8080: true, 8081: true, 8086: true, 8088: true, 8888: true, 9000: true,
	9090: true, 9200: true, 15672: true,
}

// probeResult is the outcome of identifying a service on an open port.
type probeResult struct {
	Product string
	Banner  string
	Detail  string
	TLS     bool
}

// probeConn identifies the protocol speaking on conn. It is best-effort: an
// unknown or silent service yields an empty result.
//
// For ports whose protocol is not obvious from the port number, dial may be
// used to open fresh connections for the HTTP and TLS fallbacks, since a failed
// probe can leave the first connection in an unknown state.
func probeConn(conn net.Conn, host string, port int, dial func() (net.Conn, error)) probeResult {
	switch {
	case tlsPorts[port]:
		if result, ok := probeTLS(conn, host); ok {
			return result
		}
		result, _ := probeBanner(conn)
		return result
	case httpPorts[port]:
		if result, ok := probeHTTP(conn, host); ok {
			return result
		}
		result, _ := probeBanner(conn)
		return result
	default:
		if result, ok := probeBanner(conn); ok {
			return result
		}
		// TLS before HTTP: an HTTP server that receives a TLS ClientHello
		// simply fails the handshake, whereas a TLS server answers a plaintext
		// HTTP request with a misleading plaintext "400 Bad Request".
		if result, ok := probeFresh(dial, func(c net.Conn) (probeResult, bool) {
			return probeTLS(c, host)
		}); ok {
			return result
		}
		if result, ok := probeFresh(dial, func(c net.Conn) (probeResult, bool) {
			return probeHTTP(c, host)
		}); ok {
			return result
		}
		return probeResult{}
	}
}

// probeFresh opens a new connection and runs fn against it.
func probeFresh(dial func() (net.Conn, error), fn func(net.Conn) (probeResult, bool)) (probeResult, bool) {
	if dial == nil {
		return probeResult{}, false
	}
	conn, err := dial()
	if err != nil {
		return probeResult{}, false
	}
	defer conn.Close()
	return fn(conn)
}

// probeBanner reads whatever the service sends on connect without prompting it.
func probeBanner(conn net.Conn) (probeResult, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(probeTimeout))
	buf := make([]byte, bannerMax)
	n, _ := conn.Read(buf)
	if n == 0 {
		return probeResult{}, false
	}
	banner := sanitizeBanner(buf[:n])
	if banner == "" {
		return probeResult{}, false
	}
	return probeResult{Banner: banner}, true
}

// probeHTTP sends a minimal GET and parses the status line and Server header.
func probeHTTP(conn net.Conn, host string) (probeResult, bool) {
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	request := "GET / HTTP/1.0\r\nHost: " + host +
		"\r\nUser-Agent: tracemap/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return probeResult{}, false
	}

	data, _ := io.ReadAll(io.LimitReader(conn, httpMax))
	if len(data) == 0 {
		return probeResult{}, false
	}
	return parseHTTP(string(data))
}

// parseHTTP extracts the status line and server product from an HTTP response.
func parseHTTP(raw string) (probeResult, bool) {
	if !strings.HasPrefix(strings.ToUpper(raw), "HTTP/") {
		return probeResult{}, false
	}
	lines := strings.Split(raw, "\n")
	status := strings.TrimSpace(lines[0])

	product := ""
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "server":
			product = value
		case "x-powered-by":
			if product == "" {
				product = value
			}
		}
	}
	return probeResult{Product: product, Banner: status, Detail: status}, true
}

// probeTLS completes a TLS handshake and reads identifying details from the
// peer certificate. Certificate verification is intentionally skipped: the goal
// is identification, not trust.
func probeTLS(conn net.Conn, host string) (probeResult, bool) {
	config := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // identification only
	if net.ParseIP(host) == nil {
		config.ServerName = host
	}
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	tlsConn := tls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return probeResult{}, false
	}
	state := tlsConn.ConnectionState()

	result := probeResult{TLS: true}
	if len(state.PeerCertificates) == 0 {
		return result, true
	}

	leaf := state.PeerCertificates[0]
	result.Product = leaf.Subject.CommonName
	if result.Product == "" && len(leaf.DNSNames) > 0 {
		result.Product = leaf.DNSNames[0]
	}
	if result.Product == "" {
		result.Product = leaf.Issuer.CommonName
	}

	parts := make([]string, 0, 3)
	if len(leaf.DNSNames) > 0 {
		parts = append(parts, strings.Join(leaf.DNSNames, ","))
	}
	if issuer := leaf.Issuer.CommonName; issuer != "" {
		parts = append(parts, "issuer="+issuer)
	}
	if state.NegotiatedProtocol != "" {
		parts = append(parts, "alpn="+state.NegotiatedProtocol)
	}
	result.Detail = strings.Join(parts, " ")
	return result, true
}

// sanitizeBanner collapses a raw banner into a single printable line.
func sanitizeBanner(data []byte) string {
	var b strings.Builder
	b.Grow(len(data))
	for _, c := range data {
		switch {
		case c == '\r':
		case c == '\n' || c == '\t':
			b.WriteByte(' ')
		case c >= 32 && c < 127:
			b.WriteByte(c)
		default:
			b.WriteByte('.')
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > bannerLimit {
		out = out[:bannerLimit]
	}
	return out
}

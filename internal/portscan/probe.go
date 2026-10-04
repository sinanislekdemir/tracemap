package portscan

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strconv"
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

// ftpPorts are ports where an FTP control connection is the expected first
// exchange. On these ports the anonymous-login check runs against whatever
// answers, even if the greeting does not name FTP.
var ftpPorts = map[int]bool{21: true}

// ftpServerNames are tokens that commonly appear in an FTP 220 greeting. A
// match yields a short product label in addition to the raw banner.
var ftpServerNames = []string{
	"vsftpd", "proftpd", "pure-ftpd", "filezilla", "serv-u",
	"wu-ftpd", "microsoft ftp", "cerberus ftp", "glftpd",
}

// probeResult is the outcome of identifying a service on an open port.
type probeResult struct {
	Product      string
	Banner       string
	Detail       string
	TLS          bool
	FTPAnonymous *bool
}

// probeConn identifies the protocol speaking on conn. It is best-effort: an
// unknown or silent service yields an empty result.
//
// For ports whose protocol is not obvious from the port number, dial may be
// used to open fresh connections for the HTTP and TLS fallbacks, since a failed
// probe can leave the first connection in an unknown state.
func probeConn(conn net.Conn, host string, port int, dial func() (net.Conn, error)) probeResult {
	switch {
	case ftpPorts[port]:
		if result, ok := probeFTP(conn, false); ok {
			return result
		}
		result, _ := probeBanner(conn)
		return result
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
			// A service that greets with an FTP 220 banner may run on a
			// non-standard port; offer the anonymous check there too.
			if isFTPGreeting(result.Banner) {
				return probeAnonymous(bufio.NewReader(conn), conn, result)
			}
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

// probeFTP reads an FTP greeting and tests anonymous login. When requireKeyword
// is set the greeting must name FTP (for non-standard ports); on the FTP port a
// 220 greeting is enough. It returns the result and whether a greeting was read.
func probeFTP(conn net.Conn, requireKeyword bool) (probeResult, bool) {
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	reader := bufio.NewReader(conn)
	code, text, err := readFTPReply(reader)
	banner := sanitizeBanner([]byte(text))
	if banner == "" {
		return probeResult{}, false
	}
	result := probeResult{Banner: banner}
	if err != nil || code != 220 {
		return result, true
	}
	if requireKeyword && !strings.Contains(strings.ToLower(banner), "ftp") {
		return result, true
	}
	return probeAnonymous(reader, conn, result), true
}

// probeAnonymous attempts an anonymous FTP login on a control connection whose
// greeting has already been read, layering the product label and the login
// verdict onto result.
func probeAnonymous(reader *bufio.Reader, conn net.Conn, result probeResult) probeResult {
	if product := ftpProduct(result.Banner); product != "" {
		result.Product = product
	}
	if allowed, checked := ftpAnonymous(reader, conn); checked {
		result.FTPAnonymous = &allowed
	}
	return result
}

// ftpAnonymous sends USER anonymous (and, if challenged, PASS) and reports
// whether the server accepted the login and whether it replied to FTP commands
// at all.
func ftpAnonymous(reader *bufio.Reader, conn net.Conn) (allowed, checked bool) {
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := io.WriteString(conn, "USER anonymous\r\n"); err != nil {
		return false, false
	}
	code, _, err := readFTPReply(reader)
	if err != nil {
		return false, false
	}
	// 230 means the server logged us in without a password; some servers
	// answer 202 or another 2xx to USER anonymous.
	if code >= 200 && code < 300 {
		return true, true
	}
	// 331/332 is the password challenge; anything else is a refusal.
	if code != 331 && code != 332 {
		return false, true
	}
	if _, err := io.WriteString(conn, "PASS anonymous@traceroute.invalid\r\n"); err != nil {
		return false, true
	}
	code, _, err = readFTPReply(reader)
	if err != nil {
		return false, true
	}
	return code >= 200 && code < 300, true
}

// isFTPGreeting reports whether a banner looks like an FTP 220 greeting.
func isFTPGreeting(banner string) bool {
	trimmed := strings.TrimSpace(banner)
	if !strings.HasPrefix(trimmed, "220") {
		return false
	}
	return strings.Contains(strings.ToLower(trimmed), "ftp")
}

// ftpProduct extracts a short server name from an FTP greeting, or "".
func ftpProduct(banner string) string {
	lower := strings.ToLower(banner)
	for _, name := range ftpServerNames {
		idx := strings.Index(lower, name)
		if idx < 0 {
			continue
		}
		product := strings.TrimSpace(banner[idx:])
		if end := strings.IndexAny(product, ")\r\n"); end >= 0 {
			product = strings.TrimSpace(product[:end])
		}
		if len(product) > bannerLimit {
			product = product[:bannerLimit]
		}
		return product
	}
	return ""
}

// readFTPReply reads one FTP reply, folding multiline replies into a single
// line, and returns its numeric code and text. A code of 0 means the reply did
// not start with a three-digit code.
func readFTPReply(reader *bufio.Reader) (int, string, error) {
	first, err := reader.ReadString('\n')
	text := strings.TrimRight(first, "\r\n")
	if err != nil {
		return 0, text, err
	}
	code := ftpReplyCode(text)
	if code == 0 || len(text) < 4 || text[3] != '-' {
		return code, text, nil
	}
	// Multiline reply: keep reading until the closing "NNN " line.
	lines := []string{text}
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if err != nil {
			return code, strings.Join(lines, " "), err
		}
		if len(line) >= 4 && line[3] == ' ' && ftpReplyCode(line) == code {
			return code, strings.Join(lines, " "), nil
		}
	}
}

// ftpReplyCode parses the three-digit code at the start of an FTP reply line.
func ftpReplyCode(line string) int {
	if len(line) < 3 {
		return 0
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0
	}
	return code
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

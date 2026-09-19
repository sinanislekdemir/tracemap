package domaincheck

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// whoisFallback maps TLDs to registry WHOIS servers when the IANA referral is
// unavailable. It is deliberately small: IANA's whois is the primary path.
var whoisFallback = map[string]string{
	"com":  "whois.verisign-grs.com:43",
	"net":  "whois.verisign-grs.com:43",
	"org":  "whois.pir.org:43",
	"io":   "whois.nic.io:43",
	"dev":  "whois.nic.google:43",
	"app":  "whois.nic.google:43",
	"info": "whois.afilias.net:43",
	"co":   "whois.nic.co:43",
	"uk":   "whois.nic.uk:43",
	"de":   "whois.denic.de:43",
}

// whoisRegistration resolves registration data through classic WHOIS: ask IANA
// for the TLD's registry server, then query it for the domain.
func (a *Analyzer) whoisRegistration(ctx context.Context, domain string) (Registration, bool, error) {
	var servers []string
	if referred := a.ianaRefer(ctx, tld(domain)); referred != "" {
		servers = append(servers, referred)
	}
	if fallback, ok := whoisFallback[tld(domain)]; ok {
		servers = append(servers, fallback)
	}
	if len(servers) == 0 {
		servers = append(servers, a.whoisServer)
	}

	var lastErr error
	for _, server := range servers {
		body, err := a.whoisQuery(ctx, server, domain)
		if err != nil {
			lastErr = err
			continue
		}
		if isWhoisNotFound(body) {
			return Registration{Domain: domain}, false, nil
		}
		reg := parseWhois(domain, body)
		reg.Found = true
		reg.Source = "whois"
		return reg, true, nil
	}
	return Registration{Domain: domain}, false, lastErr
}

// ianaRefer asks whois.iana.org for the registry server that serves the TLD.
func (a *Analyzer) ianaRefer(ctx context.Context, tld string) string {
	body, err := a.whoisQuery(ctx, a.whoisServer, tld)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := splitWhoisLine(line)
		if ok && strings.EqualFold(key, "refer") {
			server := strings.TrimSpace(value)
			if server == "" {
				continue
			}
			if !strings.Contains(server, ":") {
				server += ":43"
			}
			return server
		}
	}
	return ""
}

// whoisQuery opens a WHOIS session, sends the query and returns the response.
func (a *Analyzer) whoisQuery(ctx context.Context, server, query string) (string, error) {
	conn, err := a.dial(ctx, "tcp", server)
	if err != nil {
		return "", fmt.Errorf("whois %s: %w", server, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(a.timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", fmt.Errorf("whois %s: write: %w", server, err)
	}

	data, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("whois %s: read: %w", server, err)
	}
	return string(data), nil
}

// parseWhois extracts the fields that matter from a WHOIS response.
func parseWhois(domain, body string) Registration {
	reg := Registration{Domain: domain}
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		key, value, ok := splitWhoisLine(scanner.Text())
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "creation date", "created", "created on", "registered on", "registration time", "domain registration date", "registered":
			if reg.CreatedAt == 0 {
				reg.CreatedAt, _ = parseWhoisDate(value)
			}
		case "registry expiry date", "expiry date", "expiration date", "expiration time", "expires", "expires on", "paid-till", "registrar registration expiration date":
			if reg.ExpiresAt == 0 {
				reg.ExpiresAt, _ = parseWhoisDate(value)
			}
		case "updated date", "last updated", "last update", "modified", "last modified":
			if reg.UpdatedAt == 0 {
				reg.UpdatedAt, _ = parseWhoisDate(value)
			}
		case "registrar":
			if reg.Registrar == "" && !strings.Contains(strings.ToLower(value), "whois") {
				reg.Registrar = value
			}
		case "domain status", "status":
			reg.Statuses = append(reg.Statuses, firstField(value))
		case "name server", "nserver", "nameserver":
			reg.Nameservers = append(reg.Nameservers, strings.ToLower(strings.TrimSuffix(firstField(value), ".")))
		case "dnssec":
			if reg.DNSSEC == "" {
				lower := strings.ToLower(value)
				if strings.Contains(lower, "signed") || strings.Contains(lower, "yes") {
					reg.DNSSEC = "signed"
				} else if strings.Contains(lower, "unsigned") || strings.Contains(lower, "no") {
					reg.DNSSEC = "unsigned"
				}
			}
		case "registrant organization", "registrant name", "registrant":
			if reg.Registrant == "" {
				reg.Registrant = value
			}
		case "registrant country", "country":
			if reg.Country == "" {
				reg.Country = value
			}
		}
	}
	reg.Statuses = dedupe(reg.Statuses)
	reg.Nameservers = dedupe(reg.Nameservers)
	return reg
}

// splitWhoisLine splits "Key: value" and rejects comment and separator lines.
func splitWhoisLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	at := strings.Index(line, ":")
	if at <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:at]), line[at+1:], true
}

// firstField returns the first whitespace-delimited token of value.
func firstField(value string) string {
	if fields := strings.Fields(value); len(fields) > 0 {
		return fields[0]
	}
	return value
}

// isWhoisNotFound reports whether a WHOIS response says the domain is
// unregistered or unknown.
func isWhoisNotFound(body string) bool {
	lower := strings.ToLower(body)
	markers := []string{
		"no match for",
		"no entries found",
		"no data found",
		"not found",
		"no object found",
		"domain not found",
		"no information available",
		"status: available",
		"%% no entries found",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// parseWhoisDate accepts the date layouts used by registry WHOIS servers.
func parseWhoisDate(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
		"02.01.2006",
		"January 2 2006",
		"02-January-2006",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UnixMilli(), true
		}
	}
	return 0, false
}

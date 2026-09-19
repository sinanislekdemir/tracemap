package domaincheck

import (
	"context"
	"net"
	"strings"
)

// dkimSelectors are the common DKIM selectors probed, since selectors cannot be
// enumerated from DNS.
var dkimSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
	"s1", "s2", "mandrill", "sendgrid", "mailchimp", "amazonses", "zoho",
}

// dnsReport gathers address, mail-routing and email-authentication records.
func (a *Analyzer) dnsReport(ctx context.Context, domain string) DNSReport {
	report := DNSReport{}

	if ips, err := a.resolver.LookupIP(ctx, "ip", domain); err == nil {
		for _, ip := range ips {
			report.Addresses = append(report.Addresses, ip.String())
			report.Records = append(report.Records, DNSRecord{Type: ipKind(ip), Name: domain, Value: ip.String()})
		}
	}

	if cname, err := a.resolver.LookupCNAME(ctx, domain); err == nil {
		if canonical := strings.TrimSuffix(cname, "."); canonical != "" && !strings.EqualFold(canonical, domain) {
			report.Records = append(report.Records, DNSRecord{Type: "CNAME", Name: domain, Value: canonical})
		}
	}

	if nss, err := a.resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			host := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
			if host == "" {
				continue
			}
			report.Nameservers = append(report.Nameservers, host)
			report.Records = append(report.Records, DNSRecord{Type: "NS", Name: domain, Value: host})
		}
	}

	if mxs, err := a.resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
			if host == "" {
				continue
			}
			report.MX = append(report.MX, host)
			report.Records = append(report.Records, DNSRecord{Type: "MX", Name: domain, Value: host})
		}
	}

	report.TXT = a.lookupTXT(ctx, domain)
	for _, txt := range report.TXT {
		if hasPrefixFold(txt, "v=spf1") {
			report.SPF = append(report.SPF, txt)
			report.Records = append(report.Records, DNSRecord{Type: "TXT", Name: domain, Value: txt})
		}
	}
	if len(report.SPF) > 0 {
		report.SPFPolicy = spfPolicy(report.SPF[0])
		report.SPFLookups = spfLookupCount(report.SPF[0])
	}

	dmarcName := "_dmarc." + domain
	report.DMARC = a.lookupTXT(ctx, dmarcName)
	for _, txt := range report.DMARC {
		if hasPrefixFold(txt, "v=dmarc1") {
			report.DMARCPolicy = dmarcTag(txt, "p")
			report.DMARCRUA = splitTagList(txt, "rua")
			report.Records = append(report.Records, DNSRecord{Type: "TXT", Name: dmarcName, Value: txt})
		}
	}

	for _, selector := range dkimSelectors {
		name := selector + "._domainkey." + domain
		for _, txt := range a.lookupTXT(ctx, name) {
			if hasDKIMKey(txt) {
				report.DKIM = append(report.DKIM, selector)
				report.Records = append(report.Records, DNSRecord{Type: "TXT", Name: name, Value: truncate(txt, 120)})
				break
			}
		}
	}

	report.MTASTS = a.lookupTXT(ctx, "_mta-sts."+domain)
	report.TLSRPT = a.lookupTXT(ctx, "_smtp._tls."+domain)

	report.CAA = a.queryCAA(ctx, domain)
	report.DNSKEY = a.queryHasType(ctx, domain, typeDNSKEY)
	report.DS = a.queryHasType(ctx, domain, typeDS)

	report.Nameservers = dedupe(report.Nameservers)
	report.MX = dedupe(report.MX)
	report.Addresses = dedupe(report.Addresses)
	return report
}

// lookupTXT resolves TXT records, returning nil on failure.
func (a *Analyzer) lookupTXT(ctx context.Context, name string) []string {
	records, err := a.resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil
	}
	return dedupe(records)
}

// ipKind classifies an IP as an A or AAAA record.
func ipKind(ip net.IP) string {
	if ip.To4() != nil {
		return "A"
	}
	return "AAAA"
}

// spfPolicy returns the terminal policy of an SPF record.
func spfPolicy(record string) string {
	for _, token := range strings.Fields(record) {
		mechanism := strings.TrimLeft(token, "+-~?")
		if !strings.EqualFold(mechanism, "all") {
			continue
		}
		switch {
		case strings.HasPrefix(token, "-"):
			return "fail"
		case strings.HasPrefix(token, "~"):
			return "softfail"
		case strings.HasPrefix(token, "?"):
			return "neutral"
		default:
			return "pass"
		}
	}
	return "none"
}

// spfLookupCount counts the mechanisms that cost a DNS lookup, which RFC 7208
// caps at 10.
func spfLookupCount(record string) int {
	count := 0
	for _, token := range strings.Fields(record) {
		mechanism := strings.ToLower(strings.TrimLeft(token, "+-~?"))
		switch {
		case strings.HasPrefix(mechanism, "include:"),
			strings.HasPrefix(mechanism, "exists:"),
			strings.HasPrefix(mechanism, "redirect="),
			mechanism == "a",
			strings.HasPrefix(mechanism, "a:"),
			mechanism == "mx",
			strings.HasPrefix(mechanism, "mx:"),
			mechanism == "ptr":
			count++
		}
	}
	return count
}

// dmarcTag returns the value of a DMARC tag (e.g. "p" -> "reject").
func dmarcTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), tag) {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

// splitTagList returns the comma-separated values of a DMARC tag.
func splitTagList(record, tag string) []string {
	value := dmarcTag(record, tag)
	if value == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// hasDKIMKey reports whether a DKIM TXT record carries a non-empty public key
// ("p="). An empty key means the selector is revoked, and a wildcard empty key
// is a common way to publish "no DKIM here".
func hasDKIMKey(txt string) bool {
	lower := strings.ToLower(txt)
	at := strings.Index(lower, "p=")
	if at < 0 {
		return false
	}
	value := strings.TrimSpace(txt[at+2:])
	if semi := strings.Index(value, ";"); semi >= 0 {
		value = strings.TrimSpace(value[:semi])
	}
	return value != ""
}

// hasPrefixFold reports whether s starts with prefix, case-insensitively.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

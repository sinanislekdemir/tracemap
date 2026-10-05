package domaincheck

import (
	"context"
	"net"
	"strings"
	"sync"
)

// dnsProbeConcurrency bounds the concurrent DNS queries in one report. With
// ~25 independent lookups (apex records, DKIM selectors and the raw CAA/DNSKEY/
// DS queries) running them concurrently turns the DNS phase into a few RTTs.
const dnsProbeConcurrency = 8

// dkimSelectors are the common DKIM selectors probed, since selectors cannot be
// enumerated from DNS.
var dkimSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
	"s1", "s2", "mandrill", "sendgrid", "mailchimp", "amazonses", "zoho",
}

// dnsCoreResult holds the apex lookups, kept in insertion order for the report.
type dnsCoreResult struct {
	addresses   []string
	nameservers []string
	mx          []string
	txt         []string
	spf         []string
	records     []DNSRecord
}

// dnsReport gathers address, mail-routing and email-authentication records. The
// independent lookup groups (apex records, DMARC, the DKIM selectors, MTA-STS/
// TLS-RPT and the raw CAA/DNSKEY/DS queries) run concurrently, and the results
// are folded together in a stable order.
func (a *Analyzer) dnsReport(ctx context.Context, domain string) DNSReport {
	var (
		wg      sync.WaitGroup
		core    dnsCoreResult
		dmarc   []string
		dkim    []string
		dkimRec []DNSRecord
		mtaSTS  []string
		tlsRPT  []string
		caa     []string
		dnsKey  bool
		ds      bool
	)
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	run(func() { core = a.dnsCore(ctx, domain) })
	run(func() { dmarc = a.lookupTXT(ctx, "_dmarc."+domain) })
	run(func() { dkim, dkimRec = a.dkimLookups(ctx, domain) })
	run(func() { mtaSTS = a.lookupTXT(ctx, "_mta-sts."+domain) })
	run(func() { tlsRPT = a.lookupTXT(ctx, "_smtp._tls."+domain) })
	run(func() { caa = a.queryCAA(ctx, domain) })
	run(func() { dnsKey = a.queryHasType(ctx, domain, typeDNSKEY) })
	run(func() { ds = a.queryHasType(ctx, domain, typeDS) })
	wg.Wait()

	report := DNSReport{
		Addresses:   core.addresses,
		Nameservers: core.nameservers,
		MX:          core.mx,
		TXT:         core.txt,
		SPF:         core.spf,
		DMARC:       dmarc,
		DKIM:        dkim,
		MTASTS:      mtaSTS,
		TLSRPT:      tlsRPT,
		CAA:         caa,
		DNSKEY:      dnsKey,
		DS:          ds,
	}
	report.Records = append(report.Records, core.records...)

	if len(core.spf) > 0 {
		report.SPFPolicy = spfPolicy(core.spf[0])
		report.SPFLookups = spfLookupCount(core.spf[0])
	}

	dmarcName := "_dmarc." + domain
	for _, txt := range dmarc {
		if hasPrefixFold(txt, "v=dmarc1") {
			report.DMARCPolicy = dmarcTag(txt, "p")
			report.DMARCRUA = splitTagList(txt, "rua")
			report.Records = append(report.Records, DNSRecord{Type: "TXT", Name: dmarcName, Value: txt})
		}
	}
	report.Records = append(report.Records, dkimRec...)

	report.Nameservers = dedupe(report.Nameservers)
	report.MX = dedupe(report.MX)
	report.Addresses = dedupe(report.Addresses)
	return report
}

// dnsCore gathers the apex address, mail-routing and SPF records in one pass.
func (a *Analyzer) dnsCore(ctx context.Context, domain string) dnsCoreResult {
	var res dnsCoreResult

	if ips, err := a.resolver.LookupIP(ctx, "ip", domain); err == nil {
		for _, ip := range ips {
			res.addresses = append(res.addresses, ip.String())
			res.records = append(res.records, DNSRecord{Type: ipKind(ip), Name: domain, Value: ip.String()})
		}
	}

	if cname, err := a.resolver.LookupCNAME(ctx, domain); err == nil {
		if canonical := strings.TrimSuffix(cname, "."); canonical != "" && !strings.EqualFold(canonical, domain) {
			res.records = append(res.records, DNSRecord{Type: "CNAME", Name: domain, Value: canonical})
		}
	}

	if nss, err := a.resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			host := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
			if host == "" {
				continue
			}
			res.nameservers = append(res.nameservers, host)
			res.records = append(res.records, DNSRecord{Type: "NS", Name: domain, Value: host})
		}
	}

	if mxs, err := a.resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
			if host == "" {
				continue
			}
			res.mx = append(res.mx, host)
			res.records = append(res.records, DNSRecord{Type: "MX", Name: domain, Value: host})
		}
	}

	res.txt = a.lookupTXT(ctx, domain)
	for _, txt := range res.txt {
		if hasPrefixFold(txt, "v=spf1") {
			res.spf = append(res.spf, txt)
			res.records = append(res.records, DNSRecord{Type: "TXT", Name: domain, Value: txt})
		}
	}
	return res
}

// dkimLookups probes the common DKIM selectors concurrently and returns the
// matching selectors (in selector order) with their report records.
func (a *Analyzer) dkimLookups(ctx context.Context, domain string) (selectors []string, records []DNSRecord) {
	type match struct{ txt string }
	results := make([]*match, len(dkimSelectors))
	sem := make(chan struct{}, dnsProbeConcurrency)
	var wg sync.WaitGroup
	for i, selector := range dkimSelectors {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, selector string) {
			defer wg.Done()
			defer func() { <-sem }()
			name := selector + "._domainkey." + domain
			for _, txt := range a.lookupTXT(ctx, name) {
				if hasDKIMKey(txt) {
					results[i] = &match{txt: txt}
					return
				}
			}
		}(i, selector)
	}
	wg.Wait()

	for i, result := range results {
		if result == nil {
			continue
		}
		name := dkimSelectors[i] + "._domainkey." + domain
		selectors = append(selectors, dkimSelectors[i])
		records = append(records, DNSRecord{Type: "TXT", Name: name, Value: truncate(result.txt, 120)})
	}
	return selectors, records
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

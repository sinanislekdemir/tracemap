package domaincheck

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// buildChecks turns the raw report into the security/reliability checklist.
func buildChecks(report *Report) []Check {
	checks := make([]Check, 0, 24)
	add := func(id, category, title, status, detail string) {
		checks = append(checks, Check{ID: id, Category: category, Title: title, Status: status, Detail: detail})
	}

	buildRegistrationChecks(report, add)
	buildDNSChecks(report, add)
	buildEmailChecks(report, add)
	buildWebChecks(report, add)
	return checks
}

func buildRegistrationChecks(report *Report, add func(id, category, title, status, detail string)) {
	reg := report.Registration
	if reg == nil || !reg.Found {
		detail := "No RDAP or WHOIS registration record could be retrieved."
		if reg != nil && reg.Error != "" {
			detail = "Registration lookup failed: " + reg.Error
		}
		add("reg-data", CategoryRegistration, "Registration data", StatusFail, detail)
		return
	}

	age := reg.AgeDays
	if age == 0 && reg.CreatedAt > 0 {
		age = daysSince(reg.CreatedAt)
	}
	expiry := reg.DaysToExpiry
	if expiry == 0 && reg.ExpiresAt > 0 {
		expiry = daysUntil(reg.ExpiresAt)
	}

	switch {
	case reg.CreatedAt == 0:
		add("reg-age", CategoryRegistration, "Domain age", StatusInfo, "Registration date not published.")
	case age < 0:
		add("reg-age", CategoryRegistration, "Domain age", StatusInfo, "Registration date is in the future or unknown.")
	case age < 30:
		add("reg-age", CategoryRegistration, "Domain age", StatusFail,
			fmt.Sprintf("Registered %d days ago — very new domains are a common phishing indicator.", age))
	case age < 365:
		add("reg-age", CategoryRegistration, "Domain age", StatusWarn,
			fmt.Sprintf("Registered %d days ago — less than a year old.", age))
	default:
		add("reg-age", CategoryRegistration, "Domain age", StatusPass,
			fmt.Sprintf("%d days (%s).", age, humanizeDays(age)))
	}

	switch {
	case reg.ExpiresAt == 0:
		add("reg-expiry", CategoryRegistration, "Registration expiry", StatusInfo, "Expiry date not published.")
	case expiry <= 0:
		add("reg-expiry", CategoryRegistration, "Registration expiry", StatusFail,
			"Registration has expired or is in redemption.")
	case expiry < 30:
		add("reg-expiry", CategoryRegistration, "Registration expiry", StatusWarn,
			fmt.Sprintf("Expires in %d days — renew soon.", expiry))
	default:
		add("reg-expiry", CategoryRegistration, "Registration expiry", StatusPass,
			fmt.Sprintf("Expires in %d days (%s).", expiry, formatDate(reg.ExpiresAt)))
	}

	var holds []string
	for _, status := range reg.Statuses {
		lower := strings.ToLower(status)
		if strings.Contains(lower, "hold") || strings.Contains(lower, "pendingdelete") || strings.Contains(lower, "redemption") {
			holds = append(holds, status)
		}
	}
	if len(holds) > 0 {
		add("reg-status", CategoryRegistration, "Registry status", StatusFail,
			"Domain is suspended or pending deletion: "+strings.Join(holds, ", "))
	} else if len(reg.Statuses) > 0 {
		add("reg-status", CategoryRegistration, "Registry status", StatusPass, strings.Join(reg.Statuses, ", "))
	} else {
		add("reg-status", CategoryRegistration, "Registry status", StatusInfo, "No status flags published.")
	}

	switch reg.DNSSEC {
	case "signed":
		add("reg-dnssec", CategoryRegistration, "DNSSEC delegation", StatusPass, "Registry reports the zone is DNSSEC signed.")
	case "unsigned":
		add("reg-dnssec", CategoryRegistration, "DNSSEC delegation", StatusWarn, "Registry reports the zone is not DNSSEC signed.")
	default:
		add("reg-dnssec", CategoryRegistration, "DNSSEC delegation", StatusInfo, "DNSSEC status not published.")
	}

	switch {
	case len(reg.Nameservers) >= 2:
		add("reg-ns", CategoryRegistration, "Nameserver redundancy", StatusPass,
			fmt.Sprintf("%d nameservers: %s", len(reg.Nameservers), strings.Join(reg.Nameservers, ", ")))
	case len(reg.Nameservers) == 1:
		add("reg-ns", CategoryRegistration, "Nameserver redundancy", StatusWarn,
			"Only one nameserver is published — a single point of failure.")
	default:
		add("reg-ns", CategoryRegistration, "Nameserver redundancy", StatusInfo, "Nameservers not published in registration data.")
	}

	if reg.Registrar != "" {
		detail := reg.Registrar
		if reg.Registrant != "" {
			detail += " · registrant: " + reg.Registrant
		}
		if reg.Country != "" {
			detail += " (" + reg.Country + ")"
		}
		add("reg-registrar", CategoryRegistration, "Registrar", StatusPass, detail)
	} else {
		add("reg-registrar", CategoryRegistration, "Registrar", StatusInfo, "Registrar not published (often redacted).")
	}
}

func buildDNSChecks(report *Report, add func(id, category, title, status, detail string)) {
	dns := report.DNS
	if len(dns.Addresses) > 0 {
		add("dns-resolve", CategoryDNS, "Resolves", StatusPass, strings.Join(dns.Addresses, ", "))
	} else {
		add("dns-resolve", CategoryDNS, "Resolves", StatusFail, "No A or AAAA records were found.")
	}

	if len(dns.CAA) > 0 {
		add("dns-caa", CategoryDNS, "CAA records", StatusPass, strings.Join(dns.CAA, ", "))
	} else {
		add("dns-caa", CategoryDNS, "CAA records", StatusWarn, "No CAA records — any CA may issue certificates for this domain.")
	}

	switch {
	case dns.DNSKEY && dns.DS:
		add("dns-dnssec", CategoryDNS, "DNSSEC", StatusPass, "DNSKEY published and DS present at the parent.")
	case dns.DNSKEY && !dns.DS:
		add("dns-dnssec", CategoryDNS, "DNSSEC", StatusWarn, "DNSKEY published but no DS at the parent — the chain of trust is incomplete.")
	case !dns.DNSKEY && dns.DS:
		add("dns-dnssec", CategoryDNS, "DNSSEC", StatusWarn, "DS present but no DNSKEY answered — the zone may be misconfigured.")
	default:
		add("dns-dnssec", CategoryDNS, "DNSSEC", StatusWarn, "No DNSKEY or DS — responses are not cryptographically signed.")
	}
}

func buildEmailChecks(report *Report, add func(id, category, title, status, detail string)) {
	dns := report.DNS

	switch {
	case len(dns.SPF) == 1:
		add("email-spf", CategoryEmail, "SPF", StatusPass, "One SPF record published.")
	case len(dns.SPF) == 0:
		add("email-spf", CategoryEmail, "SPF", StatusFail, "No SPF record — senders are not restricted and spoofing is easy.")
	default:
		add("email-spf", CategoryEmail, "SPF", StatusWarn,
			fmt.Sprintf("%d SPF records published — RFC 7208 requires exactly one.", len(dns.SPF)))
	}

	if len(dns.SPF) > 0 {
		switch dns.SPFPolicy {
		case "fail":
			add("email-spf-policy", CategoryEmail, "SPF policy", StatusPass, "Terminal policy is -all (hard fail).")
		case "softfail":
			add("email-spf-policy", CategoryEmail, "SPF policy", StatusPass, "Terminal policy is ~all (soft fail).")
		case "neutral":
			add("email-spf-policy", CategoryEmail, "SPF policy", StatusWarn, "Terminal policy is ?all (neutral) — offers little protection.")
		case "pass":
			add("email-spf-policy", CategoryEmail, "SPF policy", StatusFail, "Terminal policy is +all — every sender is authorised.")
		default:
			add("email-spf-policy", CategoryEmail, "SPF policy", StatusWarn, "No terminal 'all' mechanism — policy is ambiguous.")
		}

		if dns.SPFLookups <= 10 {
			add("email-spf-lookups", CategoryEmail, "SPF DNS lookups", StatusPass,
				fmt.Sprintf("%d DNS-lookup mechanisms (limit 10).", dns.SPFLookups))
		} else {
			add("email-spf-lookups", CategoryEmail, "SPF DNS lookups", StatusFail,
				fmt.Sprintf("%d DNS-lookup mechanisms exceed the limit of 10 — SPF will permerror.", dns.SPFLookups))
		}
	}

	if len(dns.DMARC) > 0 {
		add("email-dmarc", CategoryEmail, "DMARC", StatusPass, "A DMARC record is published.")
		switch dns.DMARCPolicy {
		case "reject":
			add("email-dmarc-policy", CategoryEmail, "DMARC policy", StatusPass, "p=reject — unauthenticated mail is rejected.")
		case "quarantine":
			add("email-dmarc-policy", CategoryEmail, "DMARC policy", StatusPass, "p=quarantine — unauthenticated mail is quarantined.")
		case "none":
			add("email-dmarc-policy", CategoryEmail, "DMARC policy", StatusWarn, "p=none — monitoring only, no enforcement.")
		default:
			add("email-dmarc-policy", CategoryEmail, "DMARC policy", StatusWarn, "No p= policy found in the DMARC record.")
		}
		if len(dns.DMARCRUA) > 0 {
			add("email-dmarc-rua", CategoryEmail, "DMARC reporting", StatusPass, "Aggregate reports: "+strings.Join(dns.DMARCRUA, ", "))
		}
	} else {
		add("email-dmarc", CategoryEmail, "DMARC", StatusFail, "No DMARC record — spoofed mail is not policed or reported.")
	}

	if len(dns.DKIM) > 0 {
		add("email-dkim", CategoryEmail, "DKIM", StatusPass, "Selector(s) found: "+strings.Join(dns.DKIM, ", "))
	} else {
		add("email-dkim", CategoryEmail, "DKIM", StatusWarn,
			"No DKIM key found on common selectors — signing may use a custom selector or be absent.")
	}

	if len(dns.MTASTS) > 0 {
		add("email-mta-sts", CategoryEmail, "MTA-STS", StatusPass, "MTA-STS policy published.")
	} else {
		add("email-mta-sts", CategoryEmail, "MTA-STS", StatusInfo, "No MTA-STS policy — inbound TLS is not enforced.")
	}
	if len(dns.TLSRPT) > 0 {
		add("email-tls-rpt", CategoryEmail, "TLS-RPT", StatusPass, "TLS reporting published.")
	} else {
		add("email-tls-rpt", CategoryEmail, "TLS-RPT", StatusInfo, "No TLS-RPT record — TLS failures are not reported.")
	}
}

func buildWebChecks(report *Report, add func(id, category, title, status, detail string)) {
	web := report.Web

	if web.HTTPS {
		add("web-https", CategoryWeb, "HTTPS", StatusPass, fmt.Sprintf("HTTPS responds with HTTP %d.", web.HTTPStatus))
	} else if web.Error != "" {
		add("web-https", CategoryWeb, "HTTPS", StatusWarn, "HTTPS probe failed: "+web.Error)
	} else {
		add("web-https", CategoryWeb, "HTTPS", StatusWarn, "HTTPS is not available.")
	}

	if web.RedirectsHTTPS {
		add("web-redirect", CategoryWeb, "HTTP → HTTPS", StatusPass, "Plain HTTP redirects to HTTPS.")
	} else {
		add("web-redirect", CategoryWeb, "HTTP → HTTPS", StatusWarn, "Plain HTTP does not redirect to HTTPS.")
	}

	switch {
	case web.CertNotAfter == 0:
		add("web-cert", CategoryWeb, "TLS certificate", StatusInfo, "No certificate details available.")
	default:
		daysLeft := web.CertDaysLeft
		if daysLeft == 0 {
			daysLeft = daysUntil(web.CertNotAfter)
		}
		switch {
		case daysLeft <= 0:
			add("web-cert", CategoryWeb, "TLS certificate", StatusFail, "The TLS certificate has expired.")
		case daysLeft < 14:
			add("web-cert", CategoryWeb, "TLS certificate", StatusWarn,
				fmt.Sprintf("Certificate expires in %d days.", daysLeft))
		default:
			add("web-cert", CategoryWeb, "TLS certificate", StatusPass,
				fmt.Sprintf("Issued by %s, expires in %d days (%s).", fallback(web.CertIssuer, "unknown CA"), daysLeft, formatDate(web.CertNotAfter)))
		}
	}

	if age, ok := hstsMaxAge(web.Headers["strict-transport-security"]); ok {
		if age >= 15552000 {
			add("web-hsts", CategoryWeb, "HSTS", StatusPass, fmt.Sprintf("max-age=%d (≥ 180 days).", age))
		} else {
			add("web-hsts", CategoryWeb, "HSTS", StatusWarn, fmt.Sprintf("max-age=%d is shorter than 180 days.", age))
		}
	} else {
		add("web-hsts", CategoryWeb, "HSTS", StatusWarn, "No HSTS header — downgrade attacks are possible.")
	}

	present := 0
	for _, name := range securityHeaderNames {
		if name == "strict-transport-security" {
			continue
		}
		if web.Headers[name] != "" {
			present++
		}
	}
	switch {
	case present >= 3:
		add("web-headers", CategoryWeb, "Security headers", StatusPass,
			fmt.Sprintf("%d of %d recommended headers present.", present, len(securityHeaderNames)-1))
	case present >= 1:
		add("web-headers", CategoryWeb, "Security headers", StatusWarn,
			fmt.Sprintf("Only %d of %d recommended headers present.", present, len(securityHeaderNames)-1))
	default:
		add("web-headers", CategoryWeb, "Security headers", StatusWarn, "No CSP, frame, referrer or permissions policy headers set.")
	}

	if web.TLSVersion != "" && (web.TLSVersion == "TLS 1.0" || web.TLSVersion == "TLS 1.1") {
		add("web-tls-version", CategoryWeb, "TLS version", StatusWarn, "Obsolete "+web.TLSVersion+" in use.")
	}
}

// score weights each check (pass 1, warn 0.5, fail 0; info ignored) into a
// 0–100 score and letter grade.
func score(checks []Check) (int, string) {
	var points, total float64
	for _, check := range checks {
		switch check.Status {
		case StatusPass:
			points++
			total++
		case StatusWarn:
			points += 0.5
			total++
		case StatusFail:
			total++
		}
	}
	if total == 0 {
		return 0, "—"
	}
	value := int(points/total*100 + 0.5)
	switch {
	case value >= 90:
		return value, "A"
	case value >= 80:
		return value, "B"
	case value >= 70:
		return value, "C"
	case value >= 60:
		return value, "D"
	default:
		return value, "F"
	}
}

// hstsMaxAge parses the max-age directive of an HSTS header.
func hstsMaxAge(header string) (int, bool) {
	for _, directive := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(directive, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "max-age") {
			continue
		}
		age, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil {
			return age, true
		}
	}
	return 0, false
}

// FormatReport renders the report as a plain-text document for export.
func FormatReport(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DOMAIN ANALYSIS REPORT\n")
	fmt.Fprintf(&b, "======================\n\n")
	fmt.Fprintf(&b, "Domain:      %s\n", report.Domain)
	fmt.Fprintf(&b, "Analyzed:    %s\n", formatDate(report.AnalyzedAt))
	fmt.Fprintf(&b, "Score:       %d/100 (grade %s)\n\n", report.Score, report.Grade)

	fmt.Fprintf(&b, "CHECKLIST\n---------\n")
	for _, check := range report.Checks {
		fmt.Fprintf(&b, "[%-4s] %-28s %s\n", strings.ToUpper(check.Status), check.Title, check.Detail)
	}

	if reg := report.Registration; reg != nil {
		fmt.Fprintf(&b, "\nREGISTRATION (%s)\n-----------------\n", fallback(reg.Source, "unknown"))
		fmt.Fprintf(&b, "Registrar:    %s\n", fallback(reg.Registrar, "—"))
		fmt.Fprintf(&b, "Created:      %s\n", formatDate(reg.CreatedAt))
		fmt.Fprintf(&b, "Updated:      %s\n", formatDate(reg.UpdatedAt))
		fmt.Fprintf(&b, "Expires:      %s\n", formatDate(reg.ExpiresAt))
		fmt.Fprintf(&b, "Age:          %d days\n", reg.AgeDays)
		fmt.Fprintf(&b, "To expiry:    %d days\n", reg.DaysToExpiry)
		fmt.Fprintf(&b, "Status:       %s\n", fallback(strings.Join(reg.Statuses, ", "), "—"))
		fmt.Fprintf(&b, "Nameservers:  %s\n", fallback(strings.Join(reg.Nameservers, ", "), "—"))
		fmt.Fprintf(&b, "DNSSEC:       %s\n", fallback(reg.DNSSEC, "unknown"))
	}

	dns := report.DNS
	fmt.Fprintf(&b, "\nDNS\n---\n")
	fmt.Fprintf(&b, "Addresses:    %s\n", fallback(strings.Join(dns.Addresses, ", "), "—"))
	fmt.Fprintf(&b, "Nameservers:  %s\n", fallback(strings.Join(dns.Nameservers, ", "), "—"))
	fmt.Fprintf(&b, "MX:           %s\n", fallback(strings.Join(dns.MX, ", "), "—"))
	fmt.Fprintf(&b, "SPF:          %s\n", fallback(strings.Join(dns.SPF, " | "), "—"))
	fmt.Fprintf(&b, "DMARC:        %s\n", fallback(strings.Join(dns.DMARC, " | "), "—"))
	fmt.Fprintf(&b, "DKIM:         %s\n", fallback(strings.Join(dns.DKIM, ", "), "—"))
	fmt.Fprintf(&b, "CAA:          %s\n", fallback(strings.Join(dns.CAA, ", "), "—"))
	fmt.Fprintf(&b, "DNSSEC:       %s\n", dnssecLabel(dns.DNSKEY, dns.DS))
	fmt.Fprintf(&b, "MTA-STS:      %s\n", fallback(strings.Join(dns.MTASTS, " | "), "—"))
	fmt.Fprintf(&b, "TLS-RPT:      %s\n", fallback(strings.Join(dns.TLSRPT, " | "), "—"))

	web := report.Web
	fmt.Fprintf(&b, "\nWEB / TLS\n---------\n")
	fmt.Fprintf(&b, "URL:          %s\n", fallback(web.URL, "—"))
	fmt.Fprintf(&b, "HTTPS:        %t\n", web.HTTPS)
	fmt.Fprintf(&b, "Redirect:     %t\n", web.RedirectsHTTPS)
	fmt.Fprintf(&b, "Certificate:  %s (issuer %s, expires %s)\n", fallback(web.CertSubject, "—"), fallback(web.CertIssuer, "—"), formatDate(web.CertNotAfter))
	fmt.Fprintf(&b, "TLS version:  %s\n", fallback(web.TLSVersion, "—"))
	if len(web.Headers) > 0 {
		fmt.Fprintf(&b, "Headers:\n")
		for name, value := range web.Headers {
			fmt.Fprintf(&b, "  %-28s %s\n", name+":", value)
		}
	}
	if web.Error != "" {
		fmt.Fprintf(&b, "Error:        %s\n", web.Error)
	}

	return b.String()
}

func dnssecLabel(dnskey, ds bool) string {
	switch {
	case dnskey && ds:
		return "signed (DNSKEY + DS)"
	case dnskey:
		return "DNSKEY only (no DS)"
	case ds:
		return "DS only (no DNSKEY)"
	default:
		return "unsigned"
	}
}

func fallback(value, alt string) string {
	if strings.TrimSpace(value) == "" {
		return alt
	}
	return value
}

// formatDate renders Unix milliseconds as a UTC date, or "—" when unset.
func formatDate(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02")
}

// daysUntil returns whole days from now until ms (negative when past).
func daysUntil(ms int64) int {
	if ms <= 0 {
		return 0
	}
	return int(time.Until(time.UnixMilli(ms)).Hours() / 24)
}

// daysSince returns whole days from ms until now.
func daysSince(ms int64) int {
	if ms <= 0 {
		return 0
	}
	return int(time.Since(time.UnixMilli(ms)).Hours() / 24)
}

// humanizeDays renders a day count as years and days.
func humanizeDays(days int) string {
	if days < 365 {
		return fmt.Sprintf("%d days", days)
	}
	years := days / 365
	rest := days % 365
	if rest == 0 {
		return fmt.Sprintf("%d years", years)
	}
	return fmt.Sprintf("%d years, %d days", years, rest)
}

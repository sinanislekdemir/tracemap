package httpcheck

import (
	"fmt"
	"strings"
	"time"
)

// buildChecks turns an analyzed report into the checklist.
func buildChecks(report *Report) {
	add := func(id, category, title, status, detail string) {
		report.Checks = append(report.Checks, Check{
			ID: id, Category: category, Title: title, Status: status, Detail: detail,
		})
	}
	if report.Status == 0 {
		add("fetch", CategoryHeaders, "Reachability", StatusFail, "The endpoint did not respond.")
		return
	}
	buildHeaderChecks(report, add)
	buildCookieChecks(report, add)
	buildCacheChecks(report, add)
	buildTechChecks(report, add)
	buildTLSChecks(report, add)
}

// buildTLSChecks grades transport security.
func buildTLSChecks(report *Report, add func(id, category, title, status, detail string)) {
	if !report.HTTPS {
		add("tls-https", CategoryTLS, "HTTPS", StatusWarn, "The endpoint served the response over plain HTTP.")
		return
	}
	if report.TLS == nil {
		add("tls-https", CategoryTLS, "HTTPS", StatusPass, "The endpoint responded over HTTPS.")
		return
	}

	add("tls-https", CategoryTLS, "HTTPS", StatusPass, "The endpoint responded over HTTPS.")
	switch {
	case report.TLS.DaysLeft < 0:
		add("tls-cert", CategoryTLS, "TLS certificate", StatusFail, "The TLS certificate has expired.")
	case report.TLS.DaysLeft < 7:
		add("tls-cert", CategoryTLS, "TLS certificate", StatusFail,
			fmt.Sprintf("The TLS certificate expires in %d day(s).", report.TLS.DaysLeft))
	case report.TLS.DaysLeft < 30:
		add("tls-cert", CategoryTLS, "TLS certificate", StatusWarn,
			fmt.Sprintf("The TLS certificate expires in %d day(s).", report.TLS.DaysLeft))
	default:
		add("tls-cert", CategoryTLS, "TLS certificate", StatusPass,
			fmt.Sprintf("Certificate valid for %d more day(s).", report.TLS.DaysLeft))
	}
	if report.TLS.Version == "TLS 1.0" || report.TLS.Version == "TLS 1.1" {
		add("tls-version", CategoryTLS, "TLS version", StatusWarn,
			"Obsolete protocol negotiated: "+report.TLS.Version)
	} else if report.TLS.Version != "" {
		add("tls-version", CategoryTLS, "TLS version", StatusPass, "Negotiated "+report.TLS.Version+".")
	}
	if report.TLS.ALPN != "" {
		add("tls-alpn", CategoryTLS, "ALPN", StatusInfo, "Negotiated protocol "+report.TLS.ALPN+".")
	}
}

// scoreReport computes the weighted score and letter grade.
func scoreReport(report *Report) {
	score := 100
	for _, check := range report.Checks {
		switch check.Status {
		case StatusFail:
			score -= 12
		case StatusWarn:
			score -= 5
		}
	}
	if score < 0 {
		score = 0
	}
	report.Score = score
	report.Grade = grade(score)
}

// grade maps a score to a letter.
func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// FormatReport renders one or more endpoint analyses as a plain-text document.
func FormatReport(reports []Report) string {
	var b strings.Builder
	b.WriteString("HTTP ENDPOINT ANALYSIS REPORT\n")
	b.WriteString("=============================\n\n")
	fmt.Fprintf(&b, "Endpoints: %d\n", len(reports))

	for i, report := range reports {
		fmt.Fprintf(&b, "\n[%d] %s\n", i+1, report.URL)
		if report.Error != "" {
			fmt.Fprintf(&b, "    error: %s\n", report.Error)
			continue
		}
		fmt.Fprintf(&b, "    final:       %s\n", fallbackValue(report.FinalURL, report.URL))
		fmt.Fprintf(&b, "    status:      %d · https=%t\n", report.Status, report.HTTPS)
		if report.ContentType != "" {
			fmt.Fprintf(&b, "    content:     %s\n", report.ContentType)
		}
		if report.Server != "" {
			fmt.Fprintf(&b, "    server:      %s\n", report.Server)
		}
		fmt.Fprintf(&b, "    score:       %d/100 (grade %s)\n", report.Score, report.Grade)

		if len(report.Redirects) > 0 {
			fmt.Fprintf(&b, "\n    REDIRECTS\n")
			for _, hop := range report.Redirects {
				fmt.Fprintf(&b, "      %d %s → %s\n", hop.Status, hop.From, hop.To)
			}
		}

		fmt.Fprintf(&b, "\n    CHECKLIST\n")
		for _, check := range report.Checks {
			fmt.Fprintf(&b, "      [%-4s] %-30s %s\n", strings.ToUpper(check.Status), check.Title, check.Detail)
		}

		if len(report.Cookies) > 0 {
			fmt.Fprintf(&b, "\n    COOKIES\n")
			for _, cookie := range report.Cookies {
				fmt.Fprintf(&b, "      %-22s secure=%t httponly=%t samesite=%s session=%t",
					cookie.Name, cookie.Secure, cookie.HTTPOnly, fallbackValue(cookie.SameSite, "—"), cookie.Session)
				if cookie.Tech != "" {
					fmt.Fprintf(&b, " · %s", cookie.Tech)
				}
				if len(cookie.Flags) > 0 {
					fmt.Fprintf(&b, " · %s", strings.Join(cookie.Flags, ", "))
				}
				b.WriteString("\n")
			}
		}

		fmt.Fprintf(&b, "\n    CACHING\n")
		fmt.Fprintf(&b, "      cache-control: %s\n", fallbackValue(report.Caching.CacheControl, "—"))
		if report.Caching.Age > 0 {
			fmt.Fprintf(&b, "      age:           %ds\n", report.Caching.Age)
		}
		if len(report.Caching.Vary) > 0 {
			fmt.Fprintf(&b, "      vary:          %s\n", strings.Join(report.Caching.Vary, ", "))
		}
		if report.Caching.CDN != "" {
			fmt.Fprintf(&b, "      cdn:           %s\n", report.Caching.CDN)
		}
		fmt.Fprintf(&b, "      cacheable:     %t · shared=%t\n", report.Caching.Cacheable, report.Caching.Shared)

		if len(report.Tech) > 0 {
			fmt.Fprintf(&b, "\n    TECHNOLOGY\n")
			for _, tech := range report.Tech {
				fmt.Fprintf(&b, "      %-24s %-12s %s\n", tech.Name, tech.Category, tech.Evidence)
			}
		}

		if report.TLS != nil {
			fmt.Fprintf(&b, "\n    TLS\n")
			fmt.Fprintf(&b, "      version:  %s\n", fallbackValue(report.TLS.Version, "—"))
			fmt.Fprintf(&b, "      cipher:   %s\n", fallbackValue(report.TLS.Cipher, "—"))
			fmt.Fprintf(&b, "      alpn:     %s\n", fallbackValue(report.TLS.ALPN, "—"))
			fmt.Fprintf(&b, "      subject:  %s\n", fallbackValue(report.TLS.Subject, "—"))
			fmt.Fprintf(&b, "      issuer:   %s\n", fallbackValue(report.TLS.Issuer, "—"))
			fmt.Fprintf(&b, "      expires:  %s (%d days)\n", formatDate(report.TLS.NotAfter), report.TLS.DaysLeft)
		}

		if len(report.Headers) > 0 {
			fmt.Fprintf(&b, "\n    HEADERS\n")
			for _, header := range report.Headers {
				fmt.Fprintf(&b, "      %-30s %s\n", header.Name+":", header.Value)
			}
		}
	}
	return b.String()
}

// fallbackValue returns alt when value is blank.
func fallbackValue(value, alt string) string {
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

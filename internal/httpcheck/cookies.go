package httpcheck

import (
	"net/http"
	"sort"
	"strings"
)

// cookieSignature maps a Set-Cookie name to the technology that issues it.
type cookieSignature struct {
	// name is the lowercase needle; exact matches only when exact is true.
	name  string
	exact bool
	tech  string
}

// cookieSignatures are the well-known session and framework cookie names.
// Order matters: more specific needles come before generic ones.
var cookieSignatures = []cookieSignature{
	{name: "jsessionid", tech: "Java (Servlet)"},
	{name: "asp.net_sessionid", tech: "ASP.NET"},
	{name: ".aspnetcore.session", tech: "ASP.NET Core"},
	{name: "connect.sid", tech: "Express (Node.js)"},
	{name: "rack.session", tech: "Rack (Ruby)"},
	{name: "laravel_session", tech: "Laravel (PHP)"},
	{name: "xsrf-token", tech: "Laravel (PHP)"},
	{name: "ci_session", tech: "CodeIgniter (PHP)"},
	{name: "codeigniter", tech: "CodeIgniter (PHP)"},
	{name: "cakephp", tech: "CakePHP"},
	{name: "yiisession", tech: "Yii (PHP)"},
	{name: "symfony", tech: "Symfony (PHP)"},
	{name: "phpsessid", tech: "PHP"},
	{name: "csrftoken", exact: true, tech: "Django (Python)"},
	{name: "sessionid", exact: true, tech: "Django (Python)"},
	{name: "_rails", tech: "Ruby on Rails"},
	{name: "_session_id", tech: "Ruby on Rails"},
	{name: "wordpress_logged_in", tech: "WordPress"},
	{name: "wordpress_", tech: "WordPress"},
	{name: "wp-settings", tech: "WordPress"},
	{name: "drupal", tech: "Drupal"},
	{name: "moodle", tech: "Moodle"},
	{name: "grafana_session", tech: "Grafana"},
	{name: "jenkins", tech: "Jenkins"},
	{name: "_shopify", tech: "Shopify"},
	{name: "shopify", tech: "Shopify"},
	{name: "awsalb", tech: "AWS ALB"},
	{name: "cf_clearance", tech: "Cloudflare"},
	{name: "__cfduid", tech: "Cloudflare"},
	{name: "__cf_bm", tech: "Cloudflare"},
	{name: "incap_ses", tech: "Imperva"},
	{name: "visid_incap", tech: "Imperva"},
	{name: "bigipserver", tech: "F5 BIG-IP"},
	{name: "dtcookie", tech: "Dynatrace"},
	{name: "_ga", tech: "Google Analytics"},
	{name: "_gid", tech: "Google Analytics"},
	{name: "hubspot", tech: "HubSpot"},
	{name: "intercom", tech: "Intercom"},
	{name: "optimizely", tech: "Optimizely"},
}

// cookieTech returns the technology a cookie name indicates, or "".
func cookieTech(name string) string {
	lower := strings.ToLower(name)
	for _, sig := range cookieSignatures {
		if sig.exact {
			if lower == sig.name {
				return sig.tech
			}
			continue
		}
		if strings.Contains(lower, sig.name) {
			return sig.tech
		}
	}
	return ""
}

// analyzeCookies turns parsed Set-Cookie values into report entries.
func analyzeCookies(cookies []*http.Cookie) []Cookie {
	out := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		entry := Cookie{
			Name:     cookie.Name,
			Value:    truncate(cookie.Value, 120),
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
			SameSite: sameSiteName(cookie.SameSite),
			Tech:     cookieTech(cookie.Name),
		}
		if cookie.Expires.IsZero() {
			entry.Session = true
		} else {
			entry.Expires = cookie.Expires.UnixMilli()
		}
		if cookie.MaxAge != 0 {
			entry.MaxAge = cookie.MaxAge
		}
		entry.Flags = cookieFlags(cookie)
		out = append(out, entry)
	}
	return out
}

// cookieFlags lists the security weaknesses of a cookie.
func cookieFlags(cookie *http.Cookie) []string {
	var flags []string
	if !cookie.Secure {
		flags = append(flags, "no Secure flag")
	}
	if !cookie.HttpOnly {
		flags = append(flags, "no HttpOnly flag")
	}
	if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
		flags = append(flags, "SameSite=None without Secure")
	}
	if strings.HasPrefix(cookie.Domain, ".") {
		flags = append(flags, "shared across subdomains")
	}
	return flags
}

// buildCookieChecks reports default framework cookies and cookie misconfig.
func buildCookieChecks(report *Report, add func(id, category, title, status, detail string)) {
	if len(report.Cookies) == 0 {
		add("cookie-none", CategoryCookies, "Cookies", StatusInfo, "No Set-Cookie headers.")
		return
	}

	sort.SliceStable(report.Cookies, func(i, j int) bool {
		return report.Cookies[i].Name < report.Cookies[j].Name
	})

	for _, cookie := range report.Cookies {
		if cookie.Tech != "" {
			add("cookie-tech-"+cookie.Name, CategoryCookies, "Default framework cookie", StatusInfo,
				cookie.Name+" is issued by "+cookie.Tech+".")
		}
		if cookie.SameSite == "None" && !cookie.Secure {
			add("cookie-samesite-"+cookie.Name, CategoryCookies, "Cookie SameSite", StatusFail,
				cookie.Name+" sets SameSite=None without Secure.")
		} else if !cookie.Secure {
			add("cookie-secure-"+cookie.Name, CategoryCookies, "Cookie Secure flag", StatusWarn,
				cookie.Name+" is not marked Secure.")
		}
		if !cookie.HTTPOnly {
			add("cookie-httponly-"+cookie.Name, CategoryCookies, "Cookie HttpOnly flag", StatusWarn,
				cookie.Name+" is readable from JavaScript.")
		}
	}
}

// sameSiteName maps a SameSite constant to a label.
func sameSiteName(mode http.SameSite) string {
	switch mode {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Default"
	}
}

// truncate caps a string to n runes.
func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "…"
}

package httpcheck

import (
	"net/http"
	"strconv"
	"strings"
)

// cdnCacheHeaders maps a CDN cache-status header to the provider label.
var cdnCacheHeaders = []struct {
	header   string
	provider string
}{
	{"cf-cache-status", "Cloudflare"},
	{"x-vercel-cache", "Vercel"},
	{"x-fastly-request-id", "Fastly"},
	{"x-served-by", "Fastly/Varnish"},
	{"x-cache", "cache"},
	{"x-proxy-cache", "proxy cache"},
	{"x-azure-ref", "Azure Front Door"},
	{"x-amz-cf-id", "CloudFront"},
	{"akamai-grn", "Akamai"},
}

// analyzeCaching interprets a response's caching headers.
func analyzeCaching(header http.Header) CacheInfo {
	info := CacheInfo{
		CacheControl: header.Get("Cache-Control"),
		Pragma:       header.Get("Pragma"),
		Expires:      header.Get("Expires"),
		Age:          atoi(header.Get("Age")),
		ETag:         header.Get("ETag"),
		LastModified: header.Get("Last-Modified"),
		Vary:         splitList(header.Get("Vary")),
	}

	for _, raw := range strings.Split(info.CacheControl, ",") {
		part := strings.TrimSpace(strings.ToLower(raw))
		if part == "" {
			continue
		}
		info.Directives = append(info.Directives, part)
		name, value, _ := strings.Cut(part, "=")
		switch name {
		case "public":
			info.Public = true
		case "private":
			info.Private = true
		case "no-store":
			info.NoStore = true
		case "no-cache":
			info.NoCache = true
		case "max-age":
			info.MaxAge = atoi(value)
		case "s-maxage":
			info.SMaxAge = atoi(value)
		}
	}

	for _, candidate := range cdnCacheHeaders {
		if value := header.Get(candidate.header); value != "" {
			info.CDN = candidate.provider + ": " + candidate.header + "=" + value
			break
		}
	}

	info.Cacheable = !info.NoStore
	info.Shared = info.Public || info.SMaxAge > 0 || info.CDN != ""
	return info
}

// buildCacheChecks grades the caching policy.
func buildCacheChecks(report *Report, add func(id, category, title, status, detail string)) {
	cache := report.Caching
	headers := headerMap(report)

	switch {
	case cache.Public && len(report.Cookies) > 0:
		add("cache-public-cookie", CategoryCaching, "Public caching with cookies", StatusFail,
			"The response is publicly cacheable but sets cookies: an intermediary may serve one user's session to another.")
	case cache.NoStore:
		add("cache-store", CategoryCaching, "Cache storage", StatusInfo,
			"Cache-Control: no-store — the response is not stored.")
	case cache.Private:
		add("cache-private", CategoryCaching, "Cache scope", StatusInfo,
			"Cache-Control: private — cacheable by the browser only.")
	case cache.CacheControl == "" && cache.Expires == "" && headers["pragma"] == "":
		add("cache-policy", CategoryCaching, "Caching policy", StatusWarn,
			"No Cache-Control or Expires header: caching behaviour is left to heuristics.")
	default:
		detail := "Cache-Control: " + cache.CacheControl
		if cache.MaxAge > 0 {
			detail += " (max-age " + strconv.Itoa(cache.MaxAge) + "s)"
		}
		add("cache-policy", CategoryCaching, "Caching policy", StatusInfo, detail)
	}

	if cache.SMaxAge > 0 {
		add("cache-smaxage", CategoryCaching, "Shared cache", StatusInfo,
			"s-maxage="+strconv.Itoa(cache.SMaxAge)+"s allows shared caches to hold the response.")
	}
	if cache.CDN != "" {
		add("cache-cdn", CategoryCaching, "CDN caching", StatusInfo, "CDN cache header present · "+cache.CDN)
	}
	for _, value := range cache.Vary {
		if value == "*" {
			add("cache-vary", CategoryCaching, "Vary", StatusWarn, "Vary: * defeats intermediary caching.")
		}
	}
	if cache.ETag == "" && cache.LastModified == "" {
		add("cache-validators", CategoryCaching, "Cache validators", StatusInfo,
			"No ETag or Last-Modified: conditional requests cannot revalidate the resource.")
	} else {
		add("cache-validators", CategoryCaching, "Cache validators", StatusInfo,
			"Revalidation supported by ETag/Last-Modified.")
	}
}

// atoi parses a decimal int, returning 0 on error.
func atoi(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}

// splitList splits a comma-separated header value into trimmed entries.
func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

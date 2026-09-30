package httpcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyzeHeadersCookiesCacheTech(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc123", Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "xyz", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.5"></head>` +
			`<body><script src="/wp-content/app.js"></script></body></html>`))
	}))
	defer server.Close()

	report := Analyze(context.Background(), server.URL, Options{})

	if report.Error != "" {
		t.Fatalf("unexpected error: %s", report.Error)
	}
	if report.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", report.Status)
	}
	if report.URL != server.URL {
		t.Fatalf("url = %q, want %q", report.URL, server.URL)
	}
	if !hasTech(report.Tech, "Nginx") {
		t.Errorf("missing nginx tech: %+v", report.Tech)
	}
	if !hasTech(report.Tech, "PHP/8.2.1") {
		t.Errorf("missing PHP tech: %+v", report.Tech)
	}
	if !hasTech(report.Tech, "WordPress") {
		t.Errorf("missing WordPress tech: %+v", report.Tech)
	}

	session := findCookie(report.Cookies, "PHPSESSID")
	if session == nil {
		t.Fatalf("PHPSESSID cookie not reported: %+v", report.Cookies)
	}
	if session.Tech != "PHP" {
		t.Errorf("PHPSESSID tech = %q, want PHP", session.Tech)
	}
	if session.Secure {
		t.Errorf("PHPSESSID should not be Secure")
	}
	if !session.HTTPOnly {
		t.Errorf("PHPSESSID should be HttpOnly")
	}

	if !report.Caching.NoStore {
		t.Errorf("expected no-store caching: %+v", report.Caching)
	}
	if report.Caching.Cacheable {
		t.Errorf("no-store response should not be cacheable")
	}
	if report.Score >= 100 {
		t.Errorf("expected score below 100, got %d", report.Score)
	}
	if report.Grade == "" {
		t.Errorf("expected a grade")
	}
}

func TestAnalyzeTLSAndPublicCacheWithCookie(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=120, s-maxage=300")
		w.Header().Set("CF-Cache-Status", "HIT")
		w.Header().Set("Content-Type", "text/plain")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	report := Analyze(context.Background(), server.URL, Options{Client: server.Client()})

	if report.Error != "" {
		t.Fatalf("unexpected error: %s", report.Error)
	}
	if !report.HTTPS {
		t.Errorf("expected HTTPS")
	}
	if report.TLS == nil {
		t.Fatalf("expected TLS info")
	}
	if report.TLS.Version == "" {
		t.Errorf("expected a TLS version")
	}
	if !report.Caching.Public {
		t.Errorf("expected public cache policy: %+v", report.Caching)
	}
	if report.Caching.SMaxAge != 300 {
		t.Errorf("s-maxage = %d, want 300", report.Caching.SMaxAge)
	}
	if report.Caching.CDN == "" {
		t.Errorf("expected CDN cache detection")
	}
	if !hasCheck(report.Checks, "cache-public-cookie", StatusFail) {
		t.Errorf("expected a failing public-cache-with-cookie check: %+v", report.Checks)
	}
}

func TestAnalyzeFallsBackFromHTTPS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("plain"))
	}))
	defer server.Close()

	hostPort := strings.TrimPrefix(server.URL, "http://")
	report := Analyze(context.Background(), hostPort, Options{})

	if report.Error != "" {
		t.Fatalf("unexpected error: %s", report.Error)
	}
	if report.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", report.Status)
	}
	if report.HTTPS {
		t.Errorf("fallback endpoint should be plain HTTP")
	}
}

func TestAnalyzeUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := server.URL
	server.Close()

	report := Analyze(context.Background(), url, Options{})
	if report.Error == "" {
		t.Fatalf("expected an error for an unreachable endpoint")
	}
	if report.Grade != "F" {
		t.Errorf("grade = %q, want F", report.Grade)
	}
}

func TestCandidates(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "explicit https", raw: "https://a.test/", want: []string{"https://a.test/"}},
		{name: "explicit http", raw: "http://a.test/", want: []string{"http://a.test/"}},
		{name: "implicit", raw: "a.test", want: []string{"https://a.test", "http://a.test"}},
		{name: "empty", raw: "", want: nil},
		{name: "unsupported scheme", raw: "ftp://a.test", want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := candidates(test.raw)
			if len(got) != len(test.want) {
				t.Fatalf("candidates(%q) = %v, want %v", test.raw, got, test.want)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Fatalf("candidates(%q)[%d] = %q, want %q", test.raw, i, got[i], test.want[i])
				}
			}
		})
	}
}

func TestCookieTech(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "JSESSIONID", want: "Java (Servlet)"},
		{name: "ASP.NET_SessionId", want: "ASP.NET"},
		{name: "PHPSESSID", want: "PHP"},
		{name: "laravel_session", want: "Laravel (PHP)"},
		{name: "csrftoken", want: "Django (Python)"},
		{name: "sessionid", want: "Django (Python)"},
		{name: "_rails_session", want: "Ruby on Rails"},
		{name: "arbitrary_name", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cookieTech(test.name); got != test.want {
				t.Fatalf("cookieTech(%q) = %q, want %q", test.name, got, test.want)
			}
		})
	}
}

func TestFormatReport(t *testing.T) {
	report := Report{
		URL:    "https://example.test/",
		Status: 200,
		Grade:  "A",
		Score:  92,
		Tech:   []Tech{{Name: "nginx", Category: "server", Evidence: "Server: nginx"}},
		Checks: []Check{
			{ID: "hdr-csp", Category: CategoryHeaders, Title: "Content-Security-Policy", Status: StatusWarn, Detail: "none"},
		},
	}
	out := FormatReport([]Report{report})
	for _, want := range []string{"HTTP ENDPOINT ANALYSIS REPORT", "https://example.test/", "nginx", "Content-Security-Policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatted report missing %q:\n%s", want, out)
		}
	}
}

func hasTech(techs []Tech, name string) bool {
	for _, tech := range techs {
		if tech.Name == name {
			return true
		}
	}
	return false
}

func hasCheck(checks []Check, id, status string) bool {
	for _, check := range checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}

func findCookie(cookies []Cookie, name string) *Cookie {
	for i := range cookies {
		if cookies[i].Name == name {
			return &cookies[i]
		}
	}
	return nil
}

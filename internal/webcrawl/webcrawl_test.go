package webcrawl

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeResolver returns canned IPs for hostnames.
type fakeResolver struct {
	ips map[string][]string
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	var out []net.IP
	for _, value := range f.ips[host] {
		if ip := net.ParseIP(value); ip != nil {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	return out, nil
}

// dialTransport sends every request to addr, preserving the request URL so the
// crawler still sees the original hostnames.
func dialTransport(addr string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		},
	}
}

func TestCrawlFrontpageRobotsSitemapAndSubdomains(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /private\nSitemap: http://example.test/sitemap.xml\n")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0"?><urlset>
			<url><loc>http://example.test/sitemap-page</loc></url>
		</urlset>`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Home</title></head><body>
			<a href="/a">a</a>
			<a href="/b">b</a>
			<a href="http://sub.example.test/x">sub</a>
			<a href="http://external.test/y">external</a>
		</body></html>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>A</title><a href="/a2">deeper</a></html>`)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>B</title></html>`)
	})
	mux.HandleFunc("/private", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Private</title></html>`)
	})
	mux.HandleFunc("/sitemap-page", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Sitemap Page</title></html>`)
	})
	mux.HandleFunc("/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Sub X</title></html>`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	result := Crawl(context.Background(), "example.test", Options{
		BaseURL:  "http://example.test/",
		Client:   &http.Client{Transport: dialTransport(server.Listener.Addr().String())},
		Resolver: fakeResolver{ips: map[string][]string{"sub.example.test": {"203.0.113.7"}}},
	})

	byURL := map[string]Page{}
	for _, page := range result.Pages {
		byURL[page.URL] = page
	}

	if page, ok := byURL["http://example.test/"]; !ok {
		t.Fatalf("frontpage not fetched; pages=%v", byURL)
	} else if page.Title != "Home" {
		t.Errorf("frontpage title = %q, want Home", page.Title)
	}
	for _, want := range []string{
		"http://example.test/a",
		"http://example.test/b",
		"http://example.test/private",
		"http://example.test/sitemap-page",
		"http://sub.example.test/x",
	} {
		if _, ok := byURL[want]; !ok {
			t.Errorf("expected page %s to be fetched", want)
		}
	}
	if _, ok := byURL["http://external.test/y"]; ok {
		t.Error("external host should not be fetched")
	}

	if result.Robots == nil || result.Robots.Status != http.StatusOK {
		t.Fatalf("robots not parsed: %+v", result.Robots)
	}
	if len(result.Robots.Sitemaps) != 1 || result.Robots.Sitemaps[0] != "http://example.test/sitemap.xml" {
		t.Errorf("robots sitemaps = %v", result.Robots.Sitemaps)
	}

	foundSitemapURL := false
	for _, sitemap := range result.Sitemaps {
		for _, u := range sitemap.URLs {
			if u == "http://example.test/sitemap-page" {
				foundSitemapURL = true
			}
		}
	}
	if !foundSitemapURL {
		t.Errorf("sitemap URL not parsed: %+v", result.Sitemaps)
	}

	if !contains(result.URLs, "http://external.test/y") {
		t.Errorf("external URL should be recorded: %v", result.URLs)
	}
	if !contains(result.URLs, "http://example.test/a2") {
		t.Errorf("depth-2 link should be recorded but not fetched: %v", result.URLs)
	}
	if _, ok := byURL["http://example.test/a2"]; ok {
		t.Error("depth-2 link must not be fetched")
	}

	var sub *Subdomain
	for i := range result.Subdomains {
		if result.Subdomains[i].Name == "sub.example.test" {
			sub = &result.Subdomains[i]
		}
		if result.Subdomains[i].Name == "external.test" {
			t.Error("external host must not be a subdomain")
		}
	}
	if sub == nil {
		t.Fatalf("subdomain not discovered: %+v", result.Subdomains)
	}
	if len(sub.IPs) != 1 || sub.IPs[0] != "203.0.113.7" {
		t.Errorf("subdomain IPs = %v", sub.IPs)
	}
}

func TestCrawlFollowsFrontpageRedirectSameHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.test/home", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Home</title><a href="/next">next</a></html>`)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Next</title></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result := Crawl(context.Background(), "example.test", Options{
		BaseURL:  "http://example.test/",
		Client:   &http.Client{Transport: dialTransport(server.Listener.Addr().String())},
		Resolver: fakeResolver{},
	})

	byURL := map[string]Page{}
	for _, page := range result.Pages {
		byURL[page.URL] = page
	}
	if page, ok := byURL["http://example.test/home"]; !ok || page.Title != "Home" {
		t.Fatalf("redirected frontpage not followed: %+v", result.Pages)
	}
	if _, ok := byURL["http://example.test/next"]; !ok {
		t.Errorf("level-1 link after redirect not crawled: %+v", result.Pages)
	}
}

func TestCrawlFollowsFrontpageRedirectOtherHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.test/home", http.StatusFound)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Other</title><a href="http://other.test/x">x</a></html>`)
	})
	mux.HandleFunc("/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>X</title></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result := Crawl(context.Background(), "example.test", Options{
		BaseURL:  "http://example.test/",
		Client:   &http.Client{Transport: dialTransport(server.Listener.Addr().String())},
		Resolver: fakeResolver{},
	})

	byURL := map[string]Page{}
	for _, page := range result.Pages {
		byURL[page.URL] = page
	}
	if page, ok := byURL["http://other.test/home"]; !ok || page.Title != "Other" {
		t.Fatalf("cross-host redirect not followed: %+v", result.Pages)
	}
	if _, ok := byURL["http://other.test/x"]; !ok {
		t.Errorf("same-site link on redirected host not crawled: %+v", result.Pages)
	}
}

func TestCrawlLogsAttempts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Home</title>
			<a href="/ok">ok</a><a href="/missing">missing</a></html>`)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>OK</title></html>`)
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	var mu sync.Mutex
	var logs []string
	Crawl(context.Background(), "example.test", Options{
		BaseURL:  "http://example.test/",
		Client:   &http.Client{Transport: dialTransport(server.Listener.Addr().String())},
		Resolver: fakeResolver{},
		OnLog: func(_, message string) {
			mu.Lock()
			logs = append(logs, message)
			mu.Unlock()
		},
	})

	joined := strings.Join(logs, "\n")
	for _, want := range []string{
		"crawl start",
		"GET http://example.test/",
		"robots.txt",
		"GET http://example.test/ok",
		"GET http://example.test/missing",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("crawl log missing %q; got:\n%s", want, joined)
		}
	}
}

func TestWWWHost(t *testing.T) {
	cases := []struct{ domain, want string }{
		{"example.com", "www.example.com"},
		{"www.example.com", ""},
		{"127.0.0.1", ""},
		{"::1", ""},
		{"2001:db8::1", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := wwwHost(tc.domain); got != tc.want {
			t.Errorf("wwwHost(%q) = %q, want %q", tc.domain, got, tc.want)
		}
	}
}

func TestCrawlFallsBackToWWW(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>WWW</title></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	addr := server.Listener.Addr().String()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil || !strings.HasPrefix(host, "www.") {
				return nil, fmt.Errorf("no route to %s", address)
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		},
	}

	result := Crawl(context.Background(), "example.test", Options{
		Client:   &http.Client{Transport: transport},
		Resolver: fakeResolver{},
	})
	if len(result.Pages) != 1 || result.Pages[0].URL != "http://www.example.test/" || result.Pages[0].Title != "WWW" {
		t.Fatalf("www fallback failed: %+v", result.Pages)
	}
}

func TestCrawlFallsBackToHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Plain</title></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result := Crawl(context.Background(), "example.test", Options{
		Client:   &http.Client{Transport: dialTransport(server.Listener.Addr().String())},
		Resolver: fakeResolver{},
	})
	if len(result.Pages) != 1 || result.Pages[0].Title != "Plain" {
		t.Fatalf("http fallback failed: %+v", result.Pages)
	}
}

func TestCrawlTruncatesLargeBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>Big</title>"+strings.Repeat("x", 4096)+"</html>")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result := Crawl(context.Background(), "example.test", Options{
		BaseURL:      "http://example.test/",
		MaxBodyBytes: 64,
		Client:       &http.Client{Transport: dialTransport(server.Listener.Addr().String())},
		Resolver:     fakeResolver{},
	})
	if len(result.Pages) != 1 {
		t.Fatalf("pages = %+v", result.Pages)
	}
	if !result.Pages[0].Truncated {
		t.Error("expected truncated page")
	}
	if len(result.Pages[0].HTML) != 64 {
		t.Errorf("stored body length = %d, want 64", len(result.Pages[0].HTML))
	}
}

func TestParseRobots(t *testing.T) {
	sitemaps, paths := parseRobots("# comment\nUser-agent: *\nDisallow: /admin\nAllow: /admin/public\nSitemap: http://example.test/sitemap.xml\n")
	if len(sitemaps) != 1 || sitemaps[0] != "http://example.test/sitemap.xml" {
		t.Errorf("sitemaps = %v", sitemaps)
	}
	if len(paths) != 2 || paths[0] != "/admin" || paths[1] != "/admin/public" {
		t.Errorf("paths = %v", paths)
	}
}

func TestParseSitemapIndex(t *testing.T) {
	urls, nested := parseSitemap([]byte(`<?xml version="1.0"?><sitemapindex>
		<sitemap><loc>http://example.test/a.xml</loc></sitemap>
	</sitemapindex>`))
	if len(urls) != 0 || len(nested) != 1 || nested[0] != "http://example.test/a.xml" {
		t.Errorf("urls=%v nested=%v", urls, nested)
	}
}

func TestParseSitemapGzip(t *testing.T) {
	body := gzipBytes(t, `<?xml version="1.0"?><urlset><url><loc>http://example.test/z</loc></url></urlset>`)
	urls, _ := parseSitemap(body)
	if len(urls) != 1 || urls[0] != "http://example.test/z" {
		t.Errorf("urls = %v", urls)
	}
}

// gzipBytes returns body compressed with gzip.
func gzipBytes(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

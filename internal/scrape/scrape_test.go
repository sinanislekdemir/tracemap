package scrape

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"traceroute/internal/httputil"
)

// collector gathers pages and assets passed to the callbacks, which run
// concurrently.
type collector struct {
	mu     sync.Mutex
	pages  []Page
	assets []Asset
	leaks  []Leak
	logs   []string
}

func (c *collector) page(p Page)   { c.mu.Lock(); c.pages = append(c.pages, p); c.mu.Unlock() }
func (c *collector) asset(a Asset) { c.mu.Lock(); c.assets = append(c.assets, a); c.mu.Unlock() }
func (c *collector) leak(l Leak)   { c.mu.Lock(); c.leaks = append(c.leaks, l); c.mu.Unlock() }
func (c *collector) log(l, m string) {
	c.mu.Lock()
	c.logs = append(c.logs, l+": "+m)
	c.mu.Unlock()
}

func (c *collector) pageURLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.pages))
	for _, p := range c.pages {
		out = append(out, p.URL)
	}
	return out
}

func (c *collector) assetURLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.assets))
	for _, a := range c.assets {
		out = append(out, a.URL)
	}
	return out
}

func newTestSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html lang="en"><head><title>Home</title>`+
			`<meta name="description" content="welcome home">`+
			`<link rel="stylesheet" href="/style.css">`+
			`<script src="/app.js"></script></head><body>`+
			`<a href="/a.html">A</a> <a href="/b.html">B</a>`+
			`<img src="/img/logo.png" alt="logo"></body></html>`)
	})
	mux.HandleFunc("/a.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Alpha secret</title></head><body>`+
			`<p>secret data here</p><a href="/c.html">C</a></body></html>`)
	})
	mux.HandleFunc("/b.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Beta</title></head><body>public info</body></html>`)
	})
	mux.HandleFunc("/c.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Gamma</title></head><body>confidential secret stuff</body></html>`)
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		io.WriteString(w, "body{color:red}")
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "console.log(1)")
	})
	mux.HandleFunc("/img/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("\x89PNG\x0d\x0a\x1a\x0a"))
	})
	return httptest.NewServer(mux)
}

func runScrape(t *testing.T, opts Options) *collector {
	t.Helper()
	c := &collector{}
	opts.OnPage = c.page
	opts.OnAsset = c.asset
	opts.OnLeak = c.leak
	opts.OnLog = c.log
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return c
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}

func TestDepthLimitsFollowing(t *testing.T) {
	srv := newTestSite(t)
	defer srv.Close()

	cases := []struct {
		depth int
		want  int
	}{
		{0, 1},
		{1, 3},
		{2, 4},
	}
	for _, tc := range cases {
		c := runScrape(t, Options{
			Seeds:       []Seed{{URL: srv.URL + "/"}},
			Depth:       tc.depth,
			Mode:        ModeHTML,
			Scope:       ScopeHost,
			Client:      srv.Client(),
			Concurrency: 2,
		})
		if len(c.pages) != tc.want {
			t.Errorf("depth %d: got %d pages %v, want %d", tc.depth, len(c.pages), c.pageURLs(), tc.want)
		}
	}
}

func TestModeSelectsAssets(t *testing.T) {
	srv := newTestSite(t)
	defer srv.Close()

	base := Options{
		Seeds:       []Seed{{URL: srv.URL + "/"}},
		Depth:       0,
		Scope:       ScopeHost,
		Client:      srv.Client(),
		Concurrency: 2,
	}

	htmlOnly := base
	htmlOnly.Mode = ModeHTML
	if c := runScrape(t, htmlOnly); len(c.assets) != 0 {
		t.Errorf("html mode downloaded %d assets, want 0", len(c.assets))
	}

	images := base
	images.Mode = ModeHTMLImages
	c := runScrape(t, images)
	if !contains(c.assetURLs(), "/img/logo.png") {
		t.Errorf("html+images missing logo: %v", c.assetURLs())
	}
	if contains(c.assetURLs(), "/style.css") || contains(c.assetURLs(), "/app.js") {
		t.Errorf("html+images downloaded non-image assets: %v", c.assetURLs())
	}

	media := base
	media.Mode = ModeHTMLMedia
	c = runScrape(t, media)
	if !contains(c.assetURLs(), "/img/logo.png") ||
		!contains(c.assetURLs(), "/style.css") ||
		!contains(c.assetURLs(), "/app.js") {
		t.Errorf("html+media missing assets: %v", c.assetURLs())
	}
}

func TestKeywordFilter(t *testing.T) {
	srv := newTestSite(t)
	defer srv.Close()

	c := runScrape(t, Options{
		Seeds:        []Seed{{URL: srv.URL + "/"}},
		Depth:        2,
		Mode:         ModeHTML,
		Scope:        ScopeHost,
		Keywords:     []string{"secret"},
		KeywordMatch: MatchAny,
		Client:       srv.Client(),
		Concurrency:  2,
	})
	urls := c.pageURLs()
	has := func(want string) bool {
		for _, u := range urls {
			if u == want {
				return true
			}
		}
		return false
	}
	if !has(srv.URL+"/a.html") || !has(srv.URL+"/c.html") {
		t.Errorf("keyword pages missing: %v", urls)
	}
	if has(srv.URL+"/") || has(srv.URL+"/b.html") {
		t.Errorf("non-keyword pages stored: %v", urls)
	}
	// Traversal continued through non-matching pages, so c.html (depth 2,
	// reachable only via a.html) was reached.
	for _, p := range c.pages {
		if strings.Contains(p.URL, "/a.html") && len(p.MatchedKeywords) == 0 {
			t.Errorf("matched keywords not recorded for a.html")
		}
	}
}

func TestNoKeywordsIndexesAll(t *testing.T) {
	srv := newTestSite(t)
	defer srv.Close()

	// No keyword list at all → every fetched page is indexed.
	c := runScrape(t, Options{
		Seeds:       []Seed{{URL: srv.URL + "/"}},
		Depth:       1,
		Mode:        ModeHTML,
		Scope:       ScopeHost,
		Client:      srv.Client(),
		Concurrency: 2,
	})
	if len(c.pages) != 3 {
		t.Fatalf("no keywords: got %d pages %v, want all 3", len(c.pages), c.pageURLs())
	}
}

func TestKeywordCaseInsensitiveAndAll(t *testing.T) {
	srv := newTestSite(t)
	defer srv.Close()

	c := runScrape(t, Options{
		Seeds:        []Seed{{URL: srv.URL + "/a.html"}},
		Depth:        0,
		Mode:         ModeHTML,
		Scope:        ScopeHost,
		Keywords:     []string{"SECRET", "Alpha"},
		KeywordMatch: MatchAll,
		Client:       srv.Client(),
	})
	if len(c.pages) != 1 {
		t.Fatalf("case-insensitive all-match: got %d pages, want 1", len(c.pages))
	}

	c = runScrape(t, Options{
		Seeds:    []Seed{{URL: srv.URL + "/b.html"}},
		Depth:    0,
		Mode:     ModeHTML,
		Scope:    ScopeHost,
		Keywords: []string{"secret"},
		Client:   srv.Client(),
	})
	if len(c.pages) != 0 {
		t.Errorf("page without keyword was stored: %v", c.pageURLs())
	}
}

func TestMaxPagesCountsOnlyIndexed(t *testing.T) {
	var mu sync.Mutex
	requests := map[string]int{}
	mux := http.NewServeMux()
	serve := func(path, body string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests[path]++
			mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, body)
		})
	}
	serve("/", `<a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>`+
		`<a href="/p4">4</a><a href="/p5">5</a><a href="/p6">6</a>`)
	serve("/p1", "hit one")
	serve("/p2", "hit two")
	serve("/p3", "hit three")
	serve("/p4", "hit four")
	serve("/p5", "nothing here")
	serve("/p6", "nothing here")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := runScrape(t, Options{
		Seeds:        []Seed{{URL: srv.URL + "/"}},
		Depth:        1,
		Mode:         ModeHTML,
		Scope:        ScopeHost,
		Keywords:     []string{"hit"},
		KeywordMatch: MatchAny,
		MaxPages:     2,
		Client:       srv.Client(),
		Concurrency:  4,
	})
	if len(c.pages) != 2 {
		t.Fatalf("indexed %d pages, want exactly 2 (MaxPages)", len(c.pages))
	}
	// The keyword-less index and p5/p6 are still fetched for traversal even
	// though they are never indexed.
	mu.Lock()
	defer mu.Unlock()
	if requests["/"] == 0 {
		t.Errorf("index page was not fetched for traversal: %v", requests)
	}
	if requests["/p5"] == 0 && requests["/p6"] == 0 {
		t.Errorf("non-matching pages were not fetched for traversal: %v", requests)
	}
}

func TestIndexTestFindsDirectoryListing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Home</title></head><body><a href="/secret/page.html">page</a></body></html>`)
	})
	mux.HandleFunc("/secret/page.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Page</title></head><body>content</body></html>`)
	})
	mux.HandleFunc("/secret/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Index of /secret/</title></head>`+
			`<body><h1>Index of /secret/</h1><a href="page.html">page.html</a></body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := runScrape(t, Options{
		Seeds:       []Seed{{URL: srv.URL + "/"}},
		Depth:       1,
		Mode:        ModeHTML,
		Scope:       ScopeHost,
		IndexTest:   true,
		Client:      srv.Client(),
		Concurrency: 2,
	})
	if len(c.leaks) != 1 {
		t.Fatalf("got %d leaks %+v, want 1 (/secret/)", len(c.leaks), c.leaks)
	}
	if !strings.HasSuffix(c.leaks[0].URL, "/secret/") || c.leaks[0].Entries == 0 {
		t.Errorf("unexpected leak: %+v", c.leaks[0])
	}

	// With the index test off, nothing is probed.
	c = runScrape(t, Options{
		Seeds:       []Seed{{URL: srv.URL + "/"}},
		Depth:       1,
		Mode:        ModeHTML,
		Scope:       ScopeHost,
		Client:      srv.Client(),
		Concurrency: 2,
	})
	if len(c.leaks) != 0 {
		t.Errorf("index test off but got leaks: %+v", c.leaks)
	}
}

func TestThrottlePausesEveryNRequests(t *testing.T) {
	srv := newTestSite(t)
	defer srv.Close()

	start := time.Now()
	runScrape(t, Options{
		Seeds:       []Seed{{URL: srv.URL + "/"}},
		Depth:       1,
		Mode:        ModeHTML,
		Scope:       ScopeHost,
		Client:      srv.Client(),
		Concurrency: 1, // sequential, so the pause is deterministic
		Delay:       40 * time.Millisecond,
		DelayEvery:  2,
	})
	// Three pages at concurrency 1 → one pause after the 2nd request.
	if elapsed := time.Since(start); elapsed < 35*time.Millisecond {
		t.Errorf("throttle did not pause: elapsed %v, want at least 35ms", elapsed)
	}
}

func TestIgnoreTLSErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Secure</title></head><body>hi</body></html>`)
	}))
	defer srv.Close()

	// A self-signed certificate is rejected by default (the engine builds its
	// own trusting transport), so nothing is stored.
	c := runScrape(t, Options{
		Seeds: []Seed{{URL: srv.URL + "/"}}, Depth: 0, Mode: ModeHTML, Concurrency: 1,
	})
	if len(c.pages) != 0 {
		t.Errorf("expected TLS verification to fail, got %d pages", len(c.pages))
	}

	// With the option set the page is fetched.
	c = runScrape(t, Options{
		Seeds: []Seed{{URL: srv.URL + "/"}}, Depth: 0, Mode: ModeHTML, Concurrency: 1,
		IgnoreTLSErrors: true,
	})
	if len(c.pages) != 1 {
		t.Errorf("ignore TLS errors: got %d pages, want 1", len(c.pages))
	}
}

func TestInsecureTransportDoesNotMutateDefault(t *testing.T) {
	tr := insecureTransport(nil)
	ht, ok := tr.(*http.Transport)
	if !ok || ht.TLSClientConfig == nil || !ht.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure transport is not configured to skip verification")
	}
	if def, ok := http.DefaultTransport.(*http.Transport); ok && def.TLSClientConfig != nil && def.TLSClientConfig.InsecureSkipVerify {
		t.Error("the process default transport was mutated")
	}
}

// uaTransport records the User-Agent of the last request.
type uaTransport struct{ ua string }

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.ua = req.Header.Get("User-Agent")
	resp := htmlResponse("<html><body>x</body></html>")
	resp.Request = req
	return resp, nil
}

func TestUserAgentSelection(t *testing.T) {
	// A supplied User-Agent is sent verbatim.
	tr := &uaTransport{}
	if err := Run(context.Background(), Options{
		Seeds:     []Seed{{URL: "http://h/"}},
		Depth:     0,
		Mode:      ModeHTML,
		Client:    &http.Client{Transport: tr},
		UserAgent: httputil.CurlUserAgent,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if tr.ua != httputil.CurlUserAgent {
		t.Errorf("User-Agent = %q, want %q", tr.ua, httputil.CurlUserAgent)
	}

	// An empty User-Agent falls back to the default browser string.
	tr = &uaTransport{}
	if err := Run(context.Background(), Options{
		Seeds:  []Seed{{URL: "http://h/"}},
		Depth:  0,
		Mode:   ModeHTML,
		Client: &http.Client{Transport: tr},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if tr.ua != httputil.BrowserUserAgent {
		t.Errorf("default User-Agent = %q, want %q", tr.ua, httputil.BrowserUserAgent)
	}
}

// fakeTransport serves canned responses and records every requested URL, so
// tests can assert which hosts were (and were not) contacted.
type fakeTransport struct {
	mu       sync.Mutex
	requests []string
	routes   map[string]func() (*http.Response, error)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req.URL.String())
	f.mu.Unlock()
	if fn, ok := f.routes[req.URL.Host]; ok {
		resp, err := fn()
		if resp != nil {
			resp.Request = req
		}
		return resp, err
	}
	return &http.Response{
		StatusCode: 404,
		Status:     "404 Not Found",
		Proto:      "HTTP/1.1",
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func htmlResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (f *fakeTransport) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func TestBaseDomainNeverChanges(t *testing.T) {
	tr := &fakeTransport{routes: map[string]func() (*http.Response, error){
		"a.example.com": func() (*http.Response, error) {
			return htmlResponse(`<html><body><a href="http://www.example.com/sub">sub</a>` +
				`<a href="http://evil.example.net/">evil</a></body></html>`), nil
		},
		"www.example.com": func() (*http.Response, error) {
			return htmlResponse(`<html><body>sub page</body></html>`), nil
		},
		"evil.example.net": func() (*http.Response, error) {
			return htmlResponse(`<html><body>should never be fetched</body></html>`), nil
		},
	}}
	c := &collector{}
	err := Run(context.Background(), Options{
		Seeds:  []Seed{{URL: "http://a.example.com/"}},
		Depth:  1,
		Mode:   ModeHTML,
		Scope:  ScopeSite,
		Client: &http.Client{Transport: tr},
		OnPage: c.page,
		OnLog:  c.log,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !contains(c.pageURLs(), "www.example.com/sub") {
		t.Errorf("same-site subdomain not crawled: %v", c.pageURLs())
	}
	if contains(tr.requested(), "evil.example.net") {
		t.Errorf("out-of-domain host was fetched: %v", tr.requested())
	}
}

func TestOutOfDomainRedirectBlocked(t *testing.T) {
	tr := &fakeTransport{routes: map[string]func() (*http.Response, error){
		"a.example.com": func() (*http.Response, error) {
			return &http.Response{
				StatusCode: 302,
				Status:     "302 Found",
				Proto:      "HTTP/1.1",
				Header:     http.Header{"Location": []string{"http://evil.example.net/"}},
				Body:       http.NoBody,
			}, nil
		},
		"evil.example.net": func() (*http.Response, error) {
			return htmlResponse(`<html><body>evil</body></html>`), nil
		},
	}}
	c := &collector{}
	err := Run(context.Background(), Options{
		Seeds:  []Seed{{URL: "http://a.example.com/go"}},
		Depth:  0,
		Mode:   ModeHTML,
		Client: &http.Client{Transport: tr},
		OnPage: c.page,
		OnLog:  c.log,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(c.pages) != 0 {
		t.Errorf("out-of-domain redirect stored a page: %v", c.pageURLs())
	}
	if contains(tr.requested(), "evil.example.net") {
		t.Errorf("redirect target was fetched: %v", tr.requested())
	}
}

func TestScopeHostBlocksSubdomain(t *testing.T) {
	tr := &fakeTransport{routes: map[string]func() (*http.Response, error){
		"a.example.com": func() (*http.Response, error) {
			return htmlResponse(`<a href="http://www.example.com/sub">sub</a>`), nil
		},
		"www.example.com": func() (*http.Response, error) {
			return htmlResponse(`<html><body>sub</body></html>`), nil
		},
	}}
	c := &collector{}
	if err := Run(context.Background(), Options{
		Seeds:  []Seed{{URL: "http://a.example.com/"}},
		Depth:  1,
		Mode:   ModeHTML,
		Scope:  ScopeHost,
		Client: &http.Client{Transport: tr},
		OnPage: c.page,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if contains(c.pageURLs(), "www.example.com/sub") {
		t.Errorf("host scope followed a subdomain link: %v", c.pageURLs())
	}
}

func TestBaseDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":       "example.com",
		"www.example.com":   "example.com",
		"a.b.example.com":   "example.com",
		"example.co.uk":     "example.co.uk",
		"www.example.co.uk": "example.co.uk",
		"127.0.0.1":         "127.0.0.1",
		"localhost":         "localhost",
	}
	for host, want := range cases {
		if got := baseDomain(host); got != want {
			t.Errorf("baseDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

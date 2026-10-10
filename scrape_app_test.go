package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type scrapeEventCollector struct {
	mu       sync.Mutex
	pages    int
	pageURLs []string
	assets   int
	done     []ScrapeDoneEvent
	errs     []string
}

func (c *scrapeEventCollector) sink(name string, payload any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch e := payload.(type) {
	case ScrapePageEvent:
		c.pages++
		c.pageURLs = append(c.pageURLs, e.URL)
	case ScrapeAssetEvent:
		c.assets++
	case ScrapeDoneEvent:
		c.done = append(c.done, e)
	case ErrorEvent:
		c.errs = append(c.errs, e.Message)
	}
}

func TestAppScrapeEndToEnd(t *testing.T) {
	t.Setenv("TRACEROUTE_DATA", t.TempDir())
	t.Setenv("TRACEROUTE_DB", "off")

	app := NewApp()
	app.startup(context.Background())
	t.Cleanup(func() { app.shutdown(context.Background()) })

	if !app.ScrapeEnabled() {
		t.Fatal("scrape should be enabled with TRACEROUTE_DATA set")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `<html><head><title>Secret portal</title></head>`+
				`<body>welcome <img src="/logo.png"> <a href="/more.html">more</a></body></html>`)
		case "/more.html":
			io.WriteString(w, `<html><head><title>More</title></head><body>nothing</body></html>`)
		case "/logo.png":
			w.Header().Set("Content-Type", "image/png")
			io.WriteString(w, "\x89PNG\x0d\x0a\x1a\x0a")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	events := &scrapeEventCollector{}
	app.SetEmitter(events.sink)

	err := app.Scrape(ScrapeRequest{
		Targets:      []ScrapeTarget{{Label: "test", URL: srv.URL + "/"}},
		Depth:        1,
		Mode:         "html+images",
		Scope:        "host",
		Keywords:     []string{"secret"},
		KeywordMatch: "any",
		Concurrency:  2,
	})
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}

	events.mu.Lock()
	pages, assets, done, pageURLs := events.pages, events.assets, len(events.done), append([]string(nil), events.pageURLs...)
	events.mu.Unlock()
	if done != 1 {
		t.Fatalf("expected 1 done event, got %d", done)
	}
	// Only "/" contains "secret"; "/more.html" is filtered out.
	if pages != 1 {
		t.Errorf("keyword filter: got %d stored pages, want 1", pages)
	}
	// A non-indexed page must never reach the pages list (scrape:page).
	for _, u := range pageURLs {
		if strings.Contains(u, "/more.html") {
			t.Errorf("non-indexed page emitted a scrape:page event: %s", u)
		}
	}
	if assets != 1 {
		t.Errorf("html+images: got %d assets, want 1", assets)
	}

	jobs, err := app.ListScrapeJobs()
	if err != nil {
		t.Fatalf("ListScrapeJobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}

	hits, err := app.SearchScrape(ScrapeQuery{Field: "title", Query: "secret"})
	if err != nil {
		t.Fatalf("SearchScrape: %v", err)
	}
	if len(hits) != 1 {
		t.Errorf("title search: got %d hits, want 1", len(hits))
	}

	if err := app.DeleteScrapeJob(jobs[0].ID); err != nil {
		t.Fatalf("DeleteScrapeJob: %v", err)
	}
	if jobs, _ := app.ListScrapeJobs(); len(jobs) != 0 {
		t.Errorf("job not deleted: %+v", jobs)
	}
}

func TestScrapeTargetURL(t *testing.T) {
	cases := map[string]string{
		"example.com":           "http://example.com/",
		"http://example.com":    "http://example.com/",
		"https://example.com/x": "https://example.com/x",
		"example.com:8080":      "http://example.com:8080/",
		"  example.com  ":       "http://example.com/",
		"":                      "",
		"ftp://example.com":     "",
	}
	for in, want := range cases {
		if got := scrapeTargetURL(in); got != want {
			t.Errorf("scrapeTargetURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComposeScrapeURL(t *testing.T) {
	cases := []struct {
		host, scheme string
		port         int
		want         string
	}{
		{"example.com", "http://", 0, "http://example.com"},
		{"example.com", "https://", 0, "https://example.com"},
		{"example.com", "http://www.", 0, "http://www.example.com"},
		{"example.com", "https://www.", 0, "https://www.example.com"},
		// An explicit port from the field.
		{"example.com", "https://", 8443, "https://example.com:8443"},
		// An explicit port in the host text wins over the field.
		{"example.com:9000", "http://", 8080, "http://example.com:9000"},
		// www is not added to an IP literal.
		{"10.0.0.1", "https://www.", 0, "https://10.0.0.1"},
		{"10.0.0.1", "http://www.", 8080, "http://10.0.0.1:8080"},
		// Path, www and port compose together.
		{"example.com/dir", "https://www.", 8443, "https://www.example.com:8443/dir"},
		// A full URL is left as-is (a port-scan web service keeps its own).
		{"https://example.com:8443/x", "http://", 0, "https://example.com:8443/x"},
		{"", "http://", 0, ""},
	}
	for _, tc := range cases {
		if got := composeScrapeURL(tc.host, tc.scheme, tc.port); got != tc.want {
			t.Errorf("composeScrapeURL(%q, %q, %d) = %q, want %q", tc.host, tc.scheme, tc.port, got, tc.want)
		}
	}
}

func TestParseScrapeTarget(t *testing.T) {
	cases := []struct {
		raw      string
		wantHost string
		wantSch  string
		wantPort int
	}{
		{"example.com", "example.com", "http://", 0},
		{"https://example.com/", "example.com", "https://", 0},
		{"http://www.example.com", "example.com", "http://www.", 0},
		{"https://example.com:8443/", "example.com", "https://", 8443},
		{"10.0.0.1:8080", "10.0.0.1", "http://", 8080},
		{"example.com/dir", "example.com/dir", "http://", 0},
	}
	for _, tc := range cases {
		spec := parseScrapeTarget(tc.raw)
		if spec.HostPath != tc.wantHost || spec.Scheme != tc.wantSch || spec.Port != tc.wantPort {
			t.Errorf("parseScrapeTarget(%q) = %+v, want host=%q scheme=%q port=%d",
				tc.raw, spec, tc.wantHost, tc.wantSch, tc.wantPort)
		}
	}
}

func TestNormalizeKeywords(t *testing.T) {
	got := normalizeKeywords([]string{" Secret ", "secret", "", "alpha"})
	if len(got) != 2 || got[0] != "Secret" || got[1] != "alpha" {
		t.Errorf("normalizeKeywords = %v, want [Secret alpha]", got)
	}
}

func TestSplitKeywords(t *testing.T) {
	// Comma (also newline and semicolon) separated, whitespace trimmed, empties
	// dropped, and a keyword may contain spaces (matched as a phrase).
	got := splitKeywords(" foo , bar,baz ; qux\nmulti word phrase ,, ")
	want := []string{"foo", "bar", "baz", "qux", "multi word phrase"}
	if len(got) != len(want) {
		t.Fatalf("splitKeywords = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitKeywords[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if kws := splitKeywords("   "); len(kws) != 0 {
		t.Errorf("blank input should yield no keywords, got %q", kws)
	}
}

package scrape

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "scrape.db"), filepath.Join(dir, "archive"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if st == nil {
		t.Fatal("Open returned nil store for a real path")
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestStoreSearchFields(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	jobID, err := st.BeginJob(ctx, Job{Label: "example.com", Depth: 1, Mode: "html", Scope: "host"})
	if err != nil {
		t.Fatalf("BeginJob: %v", err)
	}
	pageID, err := st.SavePage(ctx, jobID, Page{
		URL:             "http://example.com/a",
		FinalURL:        "http://example.com/a",
		Depth:           0,
		Status:          200,
		ContentType:     "text/html",
		Title:           "Alpha secret",
		MetaText:        "description: welcome home\n",
		MetaJSON:        `[{"key":"description","value":"welcome home"}]`,
		Text:            "hello secret world",
		HTML:            "<html><body>hello secret world<!-- marker --></body></html>",
		Size:            64,
		MatchedKeywords: []string{"secret"},
	})
	if err != nil {
		t.Fatalf("SavePage: %v", err)
	}

	assetID, err := st.SaveAsset(ctx, jobID, Asset{
		URL:      "http://example.com/img/logo.png",
		Filename: "logo.png",
		Ext:      ".png",
		MIME:     "image/png",
		Kind:     "image",
		Status:   200,
		Size:     8,
		SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Data:     []byte("\x89PNG\x0d\x0a\x1a\x0a"),
	})
	if err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	cases := []struct {
		field string
		query string
		want  string
	}{
		{"title", "alpha", "page"},
		{"meta", "welcome", "page"},
		{"url", "example.com", "page"},
		{"text", "secret", "page"},
		{"html", "marker", "page"},
		{"filename", "logo", "asset"},
	}
	for _, tc := range cases {
		hits, err := st.Search(ctx, Query{Field: tc.field, Query: tc.query})
		if err != nil {
			t.Errorf("Search(%s, %q): %v", tc.field, tc.query, err)
			continue
		}
		if len(hits) == 0 {
			t.Errorf("Search(%s, %q): no hits", tc.field, tc.query)
			continue
		}
		if hits[0].Kind != tc.want {
			t.Errorf("Search(%s, %q): first hit kind %q, want %q", tc.field, tc.query, hits[0].Kind, tc.want)
		}
		if hits[0].Snippet == "" {
			t.Errorf("Search(%s, %q): empty snippet", tc.field, tc.query)
		}
	}

	// "all" merges pages and assets, case-insensitively.
	hits, err := st.Search(ctx, Query{Field: "all", Query: "SECRET"})
	if err != nil {
		t.Fatalf("Search all: %v", err)
	}
	foundPage := false
	for _, h := range hits {
		if h.Kind == "page" && h.ID == pageID {
			foundPage = true
		}
	}
	if !foundPage {
		t.Errorf("case-insensitive search did not find the page: %+v", hits)
	}

	// Metadata and full text round-trip through LoadPage.
	d, err := st.LoadPage(ctx, pageID)
	if err != nil {
		t.Fatalf("LoadPage: %v", err)
	}
	if d.Title != "Alpha secret" || d.Text != "hello secret world" {
		t.Errorf("LoadPage mismatch: %+v", d)
	}
	if len(d.Keywords) != 1 || d.Keywords[0] != "secret" {
		t.Errorf("matched keywords not persisted: %+v", d.Keywords)
	}

	// Asset body is on disk and reachable by path.
	path, err := st.AssetPath(ctx, assetID)
	if err != nil {
		t.Fatalf("AssetPath: %v", err)
	}
	if path == "" {
		t.Fatal("AssetPath returned empty for a stored body")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("asset file missing: %v", err)
	}
}

func TestStoreDeleteJobClearsIndex(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	jobID, err := st.BeginJob(ctx, Job{Label: "x"})
	if err != nil {
		t.Fatalf("BeginJob: %v", err)
	}
	if _, err := st.SavePage(ctx, jobID, Page{URL: "http://x/a", Title: "findme", Text: "findme"}); err != nil {
		t.Fatalf("SavePage: %v", err)
	}
	if hits, _ := st.Search(ctx, Query{Field: "title", Query: "findme"}); len(hits) != 1 {
		t.Fatalf("expected 1 hit before delete, got %d", len(hits))
	}
	if err := st.DeleteJob(ctx, jobID); err != nil {
		t.Fatalf("DeleteJob: %v", err)
	}
	if hits, _ := st.Search(ctx, Query{Field: "title", Query: "findme"}); len(hits) != 0 {
		t.Errorf("FTS still returns deleted rows: %+v", hits)
	}
}

func TestStoreLeaks(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	jobID, err := st.BeginJob(ctx, Job{Label: "x"})
	if err != nil {
		t.Fatalf("BeginJob: %v", err)
	}
	if _, err := st.SaveLeak(ctx, jobID, Leak{
		URL: "http://h/secret/", Status: 200, Kind: "autoindex",
		Title: "Index of /secret/", Entries: 3, Size: 128,
	}); err != nil {
		t.Fatalf("SaveLeak: %v", err)
	}

	leaks, err := st.ListLeaks(ctx, jobID, 0)
	if err != nil {
		t.Fatalf("ListLeaks: %v", err)
	}
	if len(leaks) != 1 || leaks[0].Entries != 3 || leaks[0].Title != "Index of /secret/" {
		t.Fatalf("unexpected leaks: %+v", leaks)
	}

	jobs, err := st.ListJobs(ctx)
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Leaks != 1 {
		t.Errorf("job leak count = %+v, want 1", jobs)
	}

	if err := st.DeleteJob(ctx, jobID); err != nil {
		t.Fatalf("DeleteJob: %v", err)
	}
	if leaks, _ := st.ListLeaks(ctx, jobID, 0); len(leaks) != 0 {
		t.Errorf("leaks survived job delete: %+v", leaks)
	}
}

func TestStoreListJobs(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if _, err := st.BeginJob(ctx, Job{Label: "one"}); err != nil {
		t.Fatalf("BeginJob: %v", err)
	}
	if _, err := st.BeginJob(ctx, Job{Label: "two"}); err != nil {
		t.Fatalf("BeginJob: %v", err)
	}
	jobs, err := st.ListJobs(ctx)
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
	// Newest first.
	if jobs[0].Label != "two" {
		t.Errorf("jobs not newest-first: %+v", jobs)
	}
}

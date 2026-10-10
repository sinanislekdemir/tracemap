package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"traceroute/internal/appdata"
	"traceroute/internal/scrape"
)

// ScrapeTarget is one starting point for a scrape: a label shown in the UI and
// a URL.
type ScrapeTarget struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// ScrapeRequest starts a scrape job over one or more targets.
type ScrapeRequest struct {
	Targets      []ScrapeTarget `json:"targets"`
	Depth        int            `json:"depth"`
	Mode         string         `json:"mode"`
	Scope        string         `json:"scope"`
	Keywords     []string       `json:"keywords"`
	KeywordMatch string         `json:"keywordMatch"`
	MaxPages     int            `json:"maxPages"`
	Concurrency  int            `json:"concurrency"`
	TimeoutMs    int            `json:"timeoutMs"`
	// IndexTest probes each fetched page's directory (and its ancestors) for an
	// open directory listing.
	IndexTest bool `json:"indexTest"`
	// DelaySeconds pauses the crawl after every DelayEvery requests.
	DelaySeconds int `json:"delaySeconds"`
	DelayEvery   int `json:"delayEvery"`
	// UserAgent overrides the request User-Agent; empty uses the default Chrome
	// string.
	UserAgent string `json:"userAgent"`
	// IgnoreTLSErrors accepts invalid/self-signed TLS certificates.
	IgnoreTLSErrors bool `json:"ignoreTlsErrors"`
}

// ScrapePageEvent reports one stored document.
type ScrapePageEvent struct {
	ID      int64    `json:"id"`
	JobID   int64    `json:"jobId"`
	Target  int      `json:"target"`
	Label   string   `json:"label"`
	URL     string   `json:"url"`
	Title   string   `json:"title"`
	Status  int      `json:"status"`
	Depth   int      `json:"depth"`
	Size    int      `json:"size"`
	Matched []string `json:"matched"`
}

// ScrapeAssetEvent reports one downloaded subresource.
type ScrapeAssetEvent struct {
	ID       int64  `json:"id"`
	JobID    int64  `json:"jobId"`
	URL      string `json:"url"`
	Kind     string `json:"kind"`
	MIME     string `json:"mime"`
	Filename string `json:"filename"`
	Ext      string `json:"ext"`
	Size     int64  `json:"size"`
}

// ScrapeLeakEvent reports an open directory listing found by the index test.
type ScrapeLeakEvent struct {
	ID      int64  `json:"id"`
	JobID   int64  `json:"jobId"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	Entries int    `json:"entries"`
}

// ScrapeProgressEvent reports running scrape counts.
type ScrapeProgressEvent struct {
	JobID  int64 `json:"jobId"`
	Pages  int   `json:"pages"`
	Assets int   `json:"assets"`
	Bytes  int64 `json:"bytes"`
}

// ScrapeDoneEvent marks a scrape complete.
type ScrapeDoneEvent struct {
	JobID  int64  `json:"jobId"`
	Status string `json:"status"`
	Pages  int    `json:"pages"`
	Assets int    `json:"assets"`
	Leaks  int    `json:"leaks"`
	Bytes  int64  `json:"bytes"`
}

// ScrapeQuery selects an archive search.
type ScrapeQuery struct {
	JobID int64  `json:"jobId"`
	Field string `json:"field"`
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

// ScrapeReport captures a scrape run for a human-readable export.
type ScrapeReport struct {
	Label        string   `json:"label"`
	Targets      []string `json:"targets"`
	Depth        int      `json:"depth"`
	Mode         string   `json:"mode"`
	Scope        string   `json:"scope"`
	Keywords     []string `json:"keywords"`
	KeywordMatch string   `json:"keywordMatch"`
	Status       string   `json:"status"`
	StartedAt    int64    `json:"startedAt"`
	DurationMs   int64    `json:"durationMs"`
	UserAgent    string   `json:"userAgent"`
	DelaySeconds int      `json:"delaySeconds"`
	DelayEvery   int      `json:"delayEvery"`
	IgnoreTLS    bool     `json:"ignoreTls"`
	Pages        int      `json:"pages"`
	Assets       int      `json:"assets"`
	Leaks        int      `json:"leaks"`
	Bytes        int64    `json:"bytes"`
}

// Scrape runs a scrape job, streaming pages/assets through the scrape:* events
// and persisting everything to the local archive. It owns its own cancellation
// context, independent of traces, scans and port scans.
func (a *App) Scrape(req ScrapeRequest) error {
	ctx, end := a.scrapeOps.begin(a.ctx)
	defer end()

	if a.scrape == nil {
		message := "scraping is disabled: no data directory (set TRACEROUTE_DATA)"
		a.emit(EventScrapeError, ErrorEvent{Target: 0, Message: message})
		return errors.New(message)
	}

	seeds := make([]scrape.Seed, 0, len(req.Targets))
	for _, t := range req.Targets {
		if u := scrapeTargetURL(t.URL); u != "" {
			seeds = append(seeds, scrape.Seed{Label: strings.TrimSpace(t.Label), URL: u})
		}
	}
	if len(seeds) == 0 {
		message := "no valid scrape targets"
		a.emit(EventScrapeError, ErrorEvent{Target: 0, Message: message})
		return errors.New(message)
	}

	mode := scrape.Mode(req.Mode)
	scope := scrape.Scope(req.Scope)
	keywords := normalizeKeywords(req.Keywords)
	match := scrape.KeywordMatch(req.KeywordMatch)

	label := seeds[0].Label
	if label == "" {
		label = seeds[0].URL
	}
	if len(seeds) > 1 {
		label = fmt.Sprintf("%s (+%d)", label, len(seeds)-1)
	}

	options := scrape.Options{
		Seeds:           seeds,
		Depth:           req.Depth,
		Mode:            mode,
		Scope:           scope,
		IndexTest:       req.IndexTest,
		Keywords:        keywords,
		KeywordMatch:    match,
		MaxPages:        req.MaxPages,
		Concurrency:     req.Concurrency,
		Timeout:         time.Duration(req.TimeoutMs) * time.Millisecond,
		Delay:           time.Duration(req.DelaySeconds) * time.Second,
		DelayEvery:      req.DelayEvery,
		UserAgent:       req.UserAgent,
		IgnoreTLSErrors: req.IgnoreTLSErrors,
	}

	jobID, err := a.scrape.BeginJob(ctx, scrape.Job{
		Label: label, Depth: req.Depth, Mode: string(mode), Scope: string(scope),
		Keywords: keywords, KeywordMatch: string(match),
	})
	if err != nil {
		a.emit(EventScrapeError, ErrorEvent{Target: 0, Message: err.Error()})
		return err
	}

	var pages, assets, leaks, totalBytes int64
	options.OnLog = func(level, message string) {
		a.emit(EventScrapeLog, CrawlLogEvent{Level: level, Message: message})
	}
	options.OnPage = func(p scrape.Page) {
		id, err := a.scrape.SavePage(ctx, jobID, p)
		if err != nil {
			a.emit(EventScrapeLog, CrawlLogEvent{Level: "error", Message: "store page: " + err.Error()})
			return
		}
		atomic.AddInt64(&pages, 1)
		atomic.AddInt64(&totalBytes, int64(p.Size))
		a.emit(EventScrapePage, ScrapePageEvent{
			ID: id, JobID: jobID, Target: p.Target, Label: p.Label, URL: p.URL,
			Title: p.Title, Status: p.Status, Depth: p.Depth, Size: p.Size,
			Matched: p.MatchedKeywords,
		})
	}
	options.OnAsset = func(as scrape.Asset) {
		id, err := a.scrape.SaveAsset(ctx, jobID, as)
		if err != nil {
			a.emit(EventScrapeLog, CrawlLogEvent{Level: "error", Message: "store asset: " + err.Error()})
			return
		}
		atomic.AddInt64(&assets, 1)
		atomic.AddInt64(&totalBytes, as.Size)
		a.emit(EventScrapeAsset, ScrapeAssetEvent{
			ID: id, JobID: jobID, URL: as.URL, Kind: as.Kind, MIME: as.MIME,
			Filename: as.Filename, Ext: as.Ext, Size: as.Size,
		})
	}
	options.OnLeak = func(l scrape.Leak) {
		id, err := a.scrape.SaveLeak(ctx, jobID, l)
		if err != nil {
			a.emit(EventScrapeLog, CrawlLogEvent{Level: "error", Message: "store leak: " + err.Error()})
			return
		}
		atomic.AddInt64(&leaks, 1)
		a.emit(EventScrapeLeak, ScrapeLeakEvent{
			ID: id, JobID: jobID, URL: l.URL, Status: l.Status, Kind: l.Kind,
			Title: l.Title, Entries: l.Entries,
		})
	}
	options.OnProgress = func(p, ac int, bytes int64) {
		a.emit(EventScrapeProgress, ScrapeProgressEvent{JobID: jobID, Pages: p, Assets: ac, Bytes: bytes})
	}

	runErr := scrape.Run(ctx, options)

	status := "done"
	errMsg := ""
	switch {
	case runErr != nil:
		status, errMsg = "error", runErr.Error()
	case ctx.Err() != nil:
		status = "cancelled"
	}
	// Persist the terminal status with a fresh context so a cancelled run still
	// records its outcome.
	_ = a.scrape.FinishJob(context.Background(), jobID, status, errMsg)
	a.emit(EventScrapeDone, ScrapeDoneEvent{
		JobID:  jobID,
		Status: status,
		Pages:  int(atomic.LoadInt64(&pages)),
		Assets: int(atomic.LoadInt64(&assets)),
		Leaks:  int(atomic.LoadInt64(&leaks)),
		Bytes:  atomic.LoadInt64(&totalBytes),
	})
	if runErr != nil {
		a.emit(EventScrapeError, ErrorEvent{Target: 0, Message: runErr.Error()})
		return runErr
	}
	return nil
}

// CancelScrape stops a running scrape, if any.
func (a *App) CancelScrape() {
	a.scrapeOps.stop()
}

// ScrapeEnabled reports whether the local archive is available.
func (a *App) ScrapeEnabled() bool {
	return a.scrape != nil
}

// ScrapePath returns the scrape database path, or "" when disabled.
func (a *App) ScrapePath() string {
	if a.scrape == nil {
		return ""
	}
	return a.scrape.Path()
}

// ScrapeArchiveDir returns the directory holding downloaded media, for the
// "open archive folder" action.
func (a *App) ScrapeArchiveDir() string {
	dir := appdata.DataDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "scrape")
}

// ListScrapeJobs returns every stored job, newest first.
func (a *App) ListScrapeJobs() ([]scrape.JobSummary, error) {
	if a.scrape == nil {
		return nil, nil
	}
	return a.scrape.ListJobs(context.Background())
}

// ListScrapePages returns a job's stored documents.
func (a *App) ListScrapePages(jobID int64) ([]scrape.PageSummary, error) {
	if a.scrape == nil {
		return nil, nil
	}
	return a.scrape.ListPages(context.Background(), jobID, 0)
}

// ListScrapeAssets returns a job's stored assets, optionally filtered by kind.
func (a *App) ListScrapeAssets(jobID int64, kind string) ([]scrape.AssetSummary, error) {
	if a.scrape == nil {
		return nil, nil
	}
	return a.scrape.ListAssets(context.Background(), jobID, kind, 0)
}

// ListScrapeLeaks returns a job's open directory listings.
func (a *App) ListScrapeLeaks(jobID int64) ([]scrape.LeakSummary, error) {
	if a.scrape == nil {
		return nil, nil
	}
	return a.scrape.ListLeaks(context.Background(), jobID, 0)
}

// SearchScrape runs a field-scoped full-text search over the archive.
func (a *App) SearchScrape(q ScrapeQuery) ([]scrape.Hit, error) {
	if a.scrape == nil {
		return nil, errors.New("scraping is disabled")
	}
	return a.scrape.Search(context.Background(), scrape.Query{
		JobID: q.JobID, Field: q.Field, Query: q.Query, Limit: q.Limit,
	})
}

// LoadScrapePage returns a stored document for preview.
func (a *App) LoadScrapePage(id int64) (scrape.PageDetail, error) {
	if a.scrape == nil {
		return scrape.PageDetail{}, errors.New("scraping is disabled")
	}
	return a.scrape.LoadPage(context.Background(), id)
}

// OpenScrapeAsset returns the on-disk path of a stored asset.
func (a *App) OpenScrapeAsset(id int64) (string, error) {
	if a.scrape == nil {
		return "", errors.New("scraping is disabled")
	}
	return a.scrape.AssetPath(context.Background(), id)
}

// DeleteScrapeJob removes a job, its pages/assets and its archive directory.
func (a *App) DeleteScrapeJob(id int64) error {
	if a.scrape == nil {
		return errors.New("scraping is disabled")
	}
	return a.scrape.DeleteJob(context.Background(), id)
}

// ExportScrapeReport writes a scrape run's context as a text report to a path
// chosen by the user, returning the path (empty when cancelled).
func (a *App) ExportScrapeReport(report ScrapeReport) (string, error) {
	name := strings.TrimSpace(report.Label)
	if name == "" {
		name = "scrape"
	}
	name = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(name)
	return a.saveTextReport("Save scrape report", name+"-scrape.txt", formatScrapeReport(report))
}

// scrapeTargetURL normalizes a user-supplied target into an http(s) URL: it
// trims whitespace, defaults to http:// when no scheme is given and ensures a
// trailing slash for a bare host. It returns "" for unusable input.
func scrapeTargetURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// normalizeKeywords trims, drops empties and de-duplicates a keyword list.
func normalizeKeywords(words []string) []string {
	out := make([]string, 0, len(words))
	seen := make(map[string]bool, len(words))
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		key := strings.ToLower(w)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, w)
	}
	return out
}

// formatScrapeReport renders a scrape run as a human-readable text report.
func formatScrapeReport(report ScrapeReport) string {
	var b strings.Builder
	b.WriteString("Scrape report\n")
	b.WriteString("=============\n\n")
	fmt.Fprintf(&b, "label          %s\n", report.Label)
	fmt.Fprintf(&b, "status         %s\n", report.Status)
	fmt.Fprintf(&b, "depth          %d\n", report.Depth)
	fmt.Fprintf(&b, "mode           %s\n", report.Mode)
	fmt.Fprintf(&b, "scope          %s\n", report.Scope)
	if len(report.Keywords) > 0 {
		fmt.Fprintf(&b, "keywords       %s (%s)\n", strings.Join(report.Keywords, ", "), report.KeywordMatch)
	}
	if report.UserAgent != "" {
		fmt.Fprintf(&b, "user agent     %s\n", report.UserAgent)
	}
	if report.DelaySeconds > 0 && report.DelayEvery > 0 {
		fmt.Fprintf(&b, "throttle       %ds every %d requests\n", report.DelaySeconds, report.DelayEvery)
	}
	if report.IgnoreTLS {
		fmt.Fprintf(&b, "tls            ignore certificate errors\n")
	}
	fmt.Fprintf(&b, "pages          %d\n", report.Pages)
	fmt.Fprintf(&b, "assets         %d\n", report.Assets)
	fmt.Fprintf(&b, "index leaks    %d\n", report.Leaks)
	fmt.Fprintf(&b, "bytes          %d\n", report.Bytes)
	if report.DurationMs > 0 {
		fmt.Fprintf(&b, "duration       %s\n", (time.Duration(report.DurationMs) * time.Millisecond).Round(time.Millisecond))
	}
	b.WriteString("\ntargets\n")
	for _, t := range report.Targets {
		fmt.Fprintf(&b, "  %s\n", t)
	}
	return b.String()
}

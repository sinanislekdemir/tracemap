// Package scrape is a self-contained website scraper/archiver. It follows
// same-site links from one or more seeds, downloads documents and (depending on
// the mode) their subresources, extracts metadata and visible text, and reports
// each page and asset through callbacks. It is pure Go (net/http plus
// golang.org/x/net/html) and never shells out.
//
// A hard invariant: the base domain of every seed is fixed when the crawl
// starts and can never change. Links and redirects that leave the base domain
// are refused, so a scrape cannot wander onto an unrelated site.
package scrape

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"traceroute/internal/httputil"
	"traceroute/internal/netutil"
	"traceroute/internal/ratelimit"
)

// Mode selects which subresources are downloaded alongside the documents.
type Mode string

const (
	// ModeHTML downloads documents only.
	ModeHTML Mode = "html"
	// ModeHTMLImages also downloads images referenced by the documents.
	ModeHTMLImages Mode = "html+images"
	// ModeHTMLMedia also downloads images, stylesheets, scripts, fonts, video
	// and audio referenced by the documents.
	ModeHTMLMedia Mode = "html+media"
)

// Scope bounds which links are followed within the seed's base domain.
type Scope string

const (
	// ScopeHost follows links to the seed's exact hostname only.
	ScopeHost Scope = "host"
	// ScopeSite follows links to the base domain and its subdomains.
	ScopeSite Scope = "site"
)

// KeywordMatch selects how multiple keywords combine when filtering storage.
type KeywordMatch string

const (
	// MatchAny stores a page when it contains at least one keyword.
	MatchAny KeywordMatch = "any"
	// MatchAll stores a page only when it contains every keyword.
	MatchAll KeywordMatch = "all"
)

// Default limits, applied when the matching Options field is zero.
const (
	DefaultDepth         = 1
	DefaultMaxPages      = 500
	DefaultMaxAssets     = 2000
	DefaultMaxAssetBytes = 25 << 20
	DefaultMaxBodyBytes  = 2 << 20
	DefaultMaxTotalBytes = 500 << 20
	DefaultConcurrency   = 4
	DefaultTimeout       = 15 * time.Second
)

// errOutOfDomain marks a redirect that would leave the seed's base domain.
var errOutOfDomain = errors.New("redirect leaves base domain")

// Seed is one starting point. Label is a human-friendly name shown next to the
// target in the UI.
type Seed struct {
	Label string
	URL   string
}

// Page is one stored HTML document.
type Page struct {
	Target          int
	Label           string
	URL             string
	FinalURL        string
	Depth           int
	Status          int
	ContentType     string
	Title           string
	MetaDescription string
	MetaKeywords    string
	MetaJSON        string
	MetaText        string
	Lang            string
	Canonical       string
	Size            int
	SHA256          string
	Text            string
	HTML            string
	HTMLTruncated   bool
	MatchedKeywords []string
}

// Asset is one downloaded subresource. Data holds the body until the callback
// writes it to disk, so it is bounded by Options.MaxAssetBytes.
type Asset struct {
	Target   int
	Label    string
	PageURL  string
	URL      string
	FinalURL string
	Filename string
	Ext      string
	MIME     string
	Kind     string
	Status   int
	Size     int64
	SHA256   string
	Data     []byte
}

// Leak is an open directory listing discovered by the index test: a directory
// URL that returned an autoindex-style page exposing its contents.
type Leak struct {
	Target   int
	Label    string
	URL      string
	FinalURL string
	Status   int
	Kind     string
	Title    string
	Entries  int
	Size     int
}

// Options configures a scrape. The zero value is usable: Run fills in sensible
// defaults.
type Options struct {
	// Seeds are the starting URLs. Empty Options.Seeds is an error.
	Seeds []Seed
	// Depth is how many link levels to follow from each seed (0 = seed pages
	// only).
	Depth int
	// Mode selects which subresources are downloaded.
	Mode Mode
	// Scope bounds link following to the host or the base domain.
	Scope Scope
	// IndexTest probes each fetched page's directory and its ancestors for an
	// open directory listing (autoindex), reporting findings through OnLeak.
	IndexTest bool
	// IgnoreTLSErrors accepts invalid, expired or self-signed TLS certificates
	// (InsecureSkipVerify), so a host with a broken certificate can still be
	// scraped. It does not bypass a failed TLS handshake.
	IgnoreTLSErrors bool
	// Keywords filters storage: when non-empty, only pages whose text contains
	// a keyword (per KeywordMatch) are stored. Traversal is unaffected.
	Keywords []string
	// KeywordMatch is MatchAny (default) or MatchAll.
	KeywordMatch KeywordMatch
	// MaxPages caps how many documents are *indexed* (stored). It is a hard
	// limit; pages rejected by the keyword filter are still fetched for link
	// traversal but never count towards it.
	MaxPages int
	// MaxAssets caps how many subresources are downloaded.
	MaxAssets int
	// MaxAssetBytes caps a single subresource's size.
	MaxAssetBytes int64
	// MaxBodyBytes caps a single document's stored body.
	MaxBodyBytes int64
	// MaxTotalBytes caps the total bytes downloaded; 0 uses the default.
	MaxTotalBytes int64
	// Concurrency bounds parallel document fetches.
	Concurrency int
	// Timeout bounds a single HTTP request.
	Timeout time.Duration
	// Rate caps requests per second (0 disables).
	Rate float64
	// Delay pauses the crawl for Delay after every DelayEvery network requests
	// (a burst throttle). Either being zero disables it.
	Delay      time.Duration
	DelayEvery int
	// UserAgent is sent with every request; defaults to BrowserUserAgent.
	UserAgent string
	// Client overrides the HTTP client (used by tests). Its CheckRedirect is
	// always replaced to enforce the base-domain rule.
	Client *http.Client

	// OnPage is called for every stored document.
	OnPage func(Page)
	// OnAsset is called for every downloaded subresource.
	OnAsset func(Asset)
	// OnLeak is called for every open directory listing the index test finds.
	OnLeak func(Leak)
	// OnProgress reports running counts.
	OnProgress func(pages, assets int, bytes int64)
	// OnLog reports each fetch attempt and its outcome. level is one of
	// "info", "ok", "warn", "error".
	OnLog func(level, message string)
}

// Run executes a scrape. It returns nil on completion (including a clean
// cancellation), or the first fatal error.
func Run(ctx context.Context, opts Options) error {
	if len(opts.Seeds) == 0 {
		return errors.New("scrape: no seeds")
	}
	c := newCrawler(opts)
	return c.run(ctx)
}

// throttle pauses a crawl once every `every` requests for `delay`. The pause is
// global (all workers wait), so no request starts during the cooldown.
type throttle struct {
	mu    sync.Mutex
	every int
	delay time.Duration
	count int
	until time.Time
}

func newThrottle(delay time.Duration, every int) *throttle {
	if every <= 0 || delay <= 0 {
		return &throttle{}
	}
	return &throttle{every: every, delay: delay}
}

// wait blocks until the next request is allowed. Every `every`-th call it opens
// a `delay`-long cooldown that the following calls wait out.
func (t *throttle) wait(ctx context.Context) error {
	if t.every <= 0 {
		return nil
	}
	t.mu.Lock()
	t.count++
	waitUntil := t.until
	if t.count%t.every == 0 {
		waitUntil = time.Now().Add(t.delay)
		t.until = waitUntil
	}
	t.mu.Unlock()

	d := time.Until(waitUntil)
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type crawler struct {
	opts     Options
	page     *http.Client
	asset    *http.Client
	limiter  *ratelimit.Limiter
	throttle *throttle

	// currentDomain is the locked base domain of the seed being crawled. Seeds
	// are processed one at a time, so a single field suffices for the shared
	// redirect guard.
	currentDomain string

	mu         sync.Mutex
	seenPage   map[string]bool
	seenAsset  map[string]bool
	seenDir    map[string]bool
	pages      int64
	assets     int64
	leaks      int64
	totalBytes int64
}

func newCrawler(opts Options) *crawler {
	if opts.Mode == "" {
		opts.Mode = ModeHTML
	}
	if opts.Scope == "" {
		opts.Scope = ScopeHost
	}
	if opts.KeywordMatch == "" {
		opts.KeywordMatch = MatchAny
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = DefaultMaxPages
	}
	if opts.MaxAssets <= 0 {
		opts.MaxAssets = DefaultMaxAssets
	}
	if opts.MaxAssetBytes <= 0 {
		opts.MaxAssetBytes = DefaultMaxAssetBytes
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.MaxTotalBytes <= 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.UserAgent == "" {
		opts.UserAgent = httputil.BrowserUserAgent
	}

	c := &crawler{
		opts:      opts,
		limiter:   ratelimit.New(opts.Rate),
		throttle:  newThrottle(opts.Delay, opts.DelayEvery),
		seenPage:  map[string]bool{},
		seenAsset: map[string]bool{},
		seenDir:   map[string]bool{},
	}

	// Two clients share one transport. The page client enforces the locked
	// base domain on every redirect; the asset client does not, because a
	// referenced subresource (an image, a font, a CDN script) is an attachment
	// fetched for an in-scope page, not part of the crawl frontier.
	base := opts.Client
	var transport http.RoundTripper
	var jar http.CookieJar
	if base != nil {
		transport = base.Transport
		jar = base.Jar
	}
	if opts.IgnoreTLSErrors {
		transport = insecureTransport(transport)
	}
	c.page = &http.Client{
		Transport:     transport,
		Timeout:       opts.Timeout,
		Jar:           jar,
		CheckRedirect: c.checkPageRedirect,
	}
	c.asset = &http.Client{
		Transport:     transport,
		Timeout:       opts.Timeout,
		Jar:           jar,
		CheckRedirect: checkAssetRedirect,
	}
	return c
}

// checkPageRedirect refuses a redirect that leaves the current seed's base
// domain, so the crawl root can never be smuggled onto another site.
func (c *crawler) checkPageRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if !c.inBaseDomain(netutil.NormalizeHost(req.URL.Hostname())) {
		return errOutOfDomain
	}
	return nil
}

// checkAssetRedirect caps asset redirect chains without constraining the host.
func checkAssetRedirect(_ *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// insecureTransport returns a transport that accepts invalid, expired or
// self-signed TLS certificates. It clones the provided transport (or the
// process default) so the global transport is never mutated. A custom
// RoundTripper (as used by tests) is returned unchanged, since its TLS config
// cannot be set.
func insecureTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	t, ok := base.(*http.Transport)
	if !ok {
		return base
	}
	clone := t.Clone()
	if clone.TLSClientConfig == nil {
		clone.TLSClientConfig = &tls.Config{}
	} else {
		clone.TLSClientConfig = clone.TLSClientConfig.Clone()
	}
	clone.TLSClientConfig.InsecureSkipVerify = true
	return clone
}

// inBaseDomain reports whether host is within the locked base domain.
func (c *crawler) inBaseDomain(host string) bool {
	domain := c.currentDomain
	if domain == "" {
		return false
	}
	if net.ParseIP(domain) != nil {
		return host == domain
	}
	return netutil.IsSameSite(host, domain)
}

// site is one seed's crawl context.
type site struct {
	index  int
	label  string
	host   string
	domain string
	scope  Scope
}

func (c *crawler) run(ctx context.Context) error {
	for i, seed := range c.opts.Seeds {
		if ctx.Err() != nil {
			return nil
		}
		rawURL := strings.TrimSpace(seed.URL)
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			c.logf("warn", "invalid seed %q", seed.URL)
			continue
		}
		host := netutil.NormalizeHost(u.Hostname())
		label := strings.TrimSpace(seed.Label)
		if label == "" {
			label = host
		}
		s := site{
			index:  i,
			label:  label,
			host:   host,
			domain: baseDomain(host),
			scope:  c.opts.Scope,
		}
		// Lock the base domain for the shared redirect guard before any fetch.
		c.currentDomain = s.domain
		c.logf("info", "target %s · base domain %s", host, s.domain)
		c.crawlSeed(ctx, s, u.String())
	}
	c.logf("ok", "done · %d pages, %d assets, %d leaks, %s",
		atomic.LoadInt64(&c.pages), atomic.LoadInt64(&c.assets),
		atomic.LoadInt64(&c.leaks), humanBytes(atomic.LoadInt64(&c.totalBytes)))
	return nil
}

func (c *crawler) crawlSeed(ctx context.Context, s site, seedURL string) {
	type item struct {
		url   string
		depth int
	}
	frontier := []item{{url: seedURL, depth: 0}}

	for depth := 0; depth <= c.opts.Depth && len(frontier) > 0; depth++ {
		if ctx.Err() != nil {
			return
		}
		var (
			mu      sync.Mutex
			next    []string
			wg      sync.WaitGroup
			stopped bool
		)
		sem := make(chan struct{}, c.opts.Concurrency)
		for _, it := range frontier {
			if ctx.Err() != nil || stopped || c.limitReached(&stopped) {
				break
			}
			mu.Lock()
			dup := c.seenPage[it.url]
			if !dup {
				c.seenPage[it.url] = true
			}
			mu.Unlock()
			if dup {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(it item) {
				defer wg.Done()
				defer func() { <-sem }()
				links := c.fetchPage(ctx, s, it.url, it.depth)
				if depth < c.opts.Depth && len(links) > 0 {
					mu.Lock()
					next = append(next, links...)
					mu.Unlock()
				}
			}(it)
		}
		wg.Wait()
		frontier = nil
		for _, u := range netutil.Dedupe(next) {
			frontier = append(frontier, item{url: u, depth: depth + 1})
		}
	}
}

// fetchPage fetches one document, stores it (subject to the keyword filter),
// downloads its subresources and returns its in-scope links.
func (c *crawler) fetchPage(ctx context.Context, s site, rawURL string, depth int) []string {
	if err := c.acquire(ctx); err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		c.logf("warn", "invalid URL %s: %v", rawURL, err)
		return nil
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)

	resp, err := c.page.Do(req)
	if err != nil {
		if errors.Is(err, errOutOfDomain) {
			c.logf("warn", "redirect left base domain, skipped: %s", rawURL)
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		c.logf("error", "fetch %s: %v", rawURL, err)
		return nil
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	ct := resp.Header.Get("Content-Type")

	if !isHTML(ct) {
		c.downloadAsset(ctx, s, resp, finalURL, rawURL)
		return nil
	}

	body, truncated, err := readCapped(resp.Body, c.opts.MaxBodyBytes)
	if err != nil {
		if ctx.Err() == nil {
			c.logf("error", "read %s: %v", rawURL, err)
		}
		return nil
	}
	doc := parseHTML(body, resp.Request.URL)

	// Directory index test runs for every fetched HTML page, independent of the
	// keyword filter, since a leak can sit above a page we would not store.
	c.probeDirectories(ctx, s, rawURL)

	links := c.scopeLinks(s, doc.Links)
	matched := matchKeywords(doc.Text, c.opts.Keywords, c.opts.KeywordMatch)
	if len(c.opts.Keywords) > 0 && len(matched) == 0 {
		// A page without a keyword is fetched for traversal only: it is not
		// stored and does not count towards MaxPages.
		c.logf("warn", "skip (no keyword) %s", rawURL)
		return links
	}

	// Take an indexed-page slot. This is strict: concurrent fetches can never
	// push the stored page count past MaxPages.
	if !c.reservePage() {
		c.logf("warn", "page cap reached (%d), not indexing %s", c.opts.MaxPages, finalURL)
		return links
	}

	sum := sha256.Sum256(body)
	page := Page{
		Target:          s.index,
		Label:           s.label,
		URL:             rawURL,
		FinalURL:        finalURL,
		Depth:           depth,
		Status:          resp.StatusCode,
		ContentType:     ct,
		Title:           doc.Title,
		MetaDescription: doc.Description,
		MetaKeywords:    doc.Keywords,
		MetaJSON:        marshalMeta(doc.Meta),
		MetaText:        doc.MetaText,
		Lang:            doc.Lang,
		Canonical:       doc.Canonical,
		Size:            len(body),
		SHA256:          hex.EncodeToString(sum[:]),
		Text:            doc.Text,
		HTML:            string(body),
		HTMLTruncated:   truncated,
		MatchedKeywords: matched,
	}
	c.logf("ok", "%d %s", resp.StatusCode, finalURL)
	if c.opts.OnPage != nil {
		c.opts.OnPage(page)
	}
	c.reportProgress()

	// Download assets only for stored pages, after the keyword filter.
	for _, assetURL := range c.assetURLs(doc) {
		if ctx.Err() != nil {
			break
		}
		var stopped bool
		if c.limitReached(&stopped) {
			break
		}
		c.fetchAssetURL(ctx, s, finalURL, assetURL)
	}
	return links
}

// probeDirectories tests a page's directory and each ancestor for an open
// listing, deduplicating across the whole crawl. It is a no-op unless the index
// test is enabled.
func (c *crawler) probeDirectories(ctx context.Context, s site, pageURL string) {
	if !c.opts.IndexTest {
		return
	}
	for _, dir := range directoryURLs(pageURL) {
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		dup := c.seenDir[dir]
		if !dup {
			c.seenDir[dir] = true
		}
		c.mu.Unlock()
		if dup {
			continue
		}
		c.probeDirectory(ctx, s, dir)
	}
}

// probeDirectory fetches one directory URL and reports a listing when the
// response is an autoindex page served for that same directory.
func (c *crawler) probeDirectory(ctx context.Context, s site, dirURL string) {
	if err := c.acquire(ctx); err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dirURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	resp, err := c.page.Do(req)
	if err != nil {
		if ctx.Err() == nil && !errors.Is(err, errOutOfDomain) {
			c.logf("warn", "index probe %s: %v", dirURL, err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, _, err := readCapped(resp.Body, c.opts.MaxBodyBytes)
	if err != nil {
		return
	}
	finalURL := resp.Request.URL.String()
	if !sameDirectory(finalURL, dirURL) {
		return
	}
	title, entries, leak := analyzeIndex(body)
	if !leak {
		return
	}
	atomic.AddInt64(&c.leaks, 1)
	c.logf("ok", "DIR LISTING %s (%d entries)", dirURL, entries)
	if c.opts.OnLeak != nil {
		c.opts.OnLeak(Leak{
			Target:   s.index,
			Label:    s.label,
			URL:      dirURL,
			FinalURL: finalURL,
			Status:   resp.StatusCode,
			Kind:     "autoindex",
			Title:    title,
			Entries:  entries,
			Size:     len(body),
		})
	}
}

// assetURLs returns the subresource URLs to download for a document, according
// to the configured mode.
func (c *crawler) assetURLs(doc parsedDoc) []string {
	switch c.opts.Mode {
	case ModeHTMLImages:
		return doc.Images
	case ModeHTMLMedia:
		return append(append([]string{}, doc.Images...), doc.Resources...)
	default:
		return nil
	}
}

// scopeLinks keeps only the links whose host is within the crawl scope.
func (c *crawler) scopeLinks(s site, links []string) []string {
	out := make([]string, 0, len(links))
	for _, link := range links {
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		host := netutil.NormalizeHost(u.Hostname())
		if !c.inScope(s, host) {
			continue
		}
		out = append(out, link)
	}
	return out
}

// inScope reports whether host is within the seed's configured scope. It can
// only ever be a subset of the locked base domain.
func (c *crawler) inScope(s site, host string) bool {
	if net.ParseIP(s.domain) != nil {
		return host == s.domain
	}
	if s.scope == ScopeHost {
		return host == s.host
	}
	return netutil.IsSameSite(host, s.domain)
}

// fetchAssetURL downloads one subresource for a stored page.
func (c *crawler) fetchAssetURL(ctx context.Context, s site, pageURL, assetURL string) {
	c.mu.Lock()
	dup := c.seenAsset[assetURL]
	if !dup {
		c.seenAsset[assetURL] = true
	}
	c.mu.Unlock()
	if dup {
		return
	}
	if err := c.acquire(ctx); err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	resp, err := c.asset.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			c.logf("warn", "asset %s: %v", assetURL, err)
		}
		return
	}
	defer resp.Body.Close()
	c.downloadAsset(ctx, s, resp, resp.Request.URL.String(), pageURL)
}

// downloadAsset reads a response into memory (bounded) and reports it as an
// asset. It is used both for subresources and for non-HTML seed documents.
func (c *crawler) downloadAsset(ctx context.Context, s site, resp *http.Response, finalURL, pageURL string) {
	if resp.StatusCode >= 400 {
		c.logf("warn", "asset %d %s", resp.StatusCode, finalURL)
		return
	}
	body, _, err := readCapped(resp.Body, c.opts.MaxAssetBytes)
	if err != nil {
		if ctx.Err() == nil {
			c.logf("warn", "asset read %s: %v", finalURL, err)
		}
		return
	}
	sum := sha256.Sum256(body)
	kind := assetKind(resp.Header.Get("Content-Type"), finalURL)
	asset := Asset{
		Target:   s.index,
		Label:    s.label,
		PageURL:  pageURL,
		URL:      finalURL,
		FinalURL: finalURL,
		Filename: filenameFromURL(finalURL),
		Ext:      extFrom(finalURL, resp.Header.Get("Content-Type")),
		MIME:     mimeFrom(resp.Header.Get("Content-Type"), finalURL),
		Kind:     kind,
		Status:   resp.StatusCode,
		Size:     int64(len(body)),
		SHA256:   hex.EncodeToString(sum[:]),
		Data:     body,
	}
	atomic.AddInt64(&c.assets, 1)
	atomic.AddInt64(&c.totalBytes, asset.Size)
	c.logf("ok", "asset %s (%s)", finalURL, asset.Kind)
	if c.opts.OnAsset != nil {
		c.opts.OnAsset(asset)
	}
	c.reportProgress()
}

// reservePage claims one indexed-page slot, reporting false once MaxPages have
// been claimed. The compare-and-swap loop makes the cap strict even when pages
// finish concurrently; a page that cannot claim a slot is fetched (for its
// links) but not stored.
func (c *crawler) reservePage() bool {
	for {
		cur := atomic.LoadInt64(&c.pages)
		if cur >= int64(c.opts.MaxPages) {
			return false
		}
		if atomic.CompareAndSwapInt64(&c.pages, cur, cur+1) {
			return true
		}
	}
}

// limitReached reports whether any cap has been hit and records it so nested
// loops stop.
func (c *crawler) limitReached(stopped *bool) bool {
	if *stopped {
		return true
	}
	pages := atomic.LoadInt64(&c.pages)
	assets := atomic.LoadInt64(&c.assets)
	bytes := atomic.LoadInt64(&c.totalBytes)
	if pages >= int64(c.opts.MaxPages) {
		*stopped = true
		c.logf("warn", "page cap reached (%d), stopping", c.opts.MaxPages)
		return true
	}
	if assets >= int64(c.opts.MaxAssets) {
		*stopped = true
		c.logf("warn", "asset cap reached (%d), stopping", c.opts.MaxAssets)
		return true
	}
	if bytes >= c.opts.MaxTotalBytes {
		*stopped = true
		c.logf("warn", "byte cap reached (%s), stopping", humanBytes(c.opts.MaxTotalBytes))
		return true
	}
	return false
}

func (c *crawler) reportProgress() {
	if c.opts.OnProgress != nil {
		c.opts.OnProgress(int(atomic.LoadInt64(&c.pages)), int(atomic.LoadInt64(&c.assets)), atomic.LoadInt64(&c.totalBytes))
	}
}

// acquire applies the burst throttle and the per-second rate limit before a
// network request.
func (c *crawler) acquire(ctx context.Context) error {
	if err := c.throttle.wait(ctx); err != nil {
		return err
	}
	return c.limiter.Wait(ctx)
}

func (c *crawler) logf(level, format string, args ...any) {
	if c.opts.OnLog != nil {
		c.opts.OnLog(level, fmt.Sprintf(format, args...))
	}
}

// readCapped reads at most max bytes, reporting whether the source was longer.
func readCapped(r io.Reader, max int64) ([]byte, bool, error) {
	if max <= 0 {
		max = DefaultMaxBodyBytes
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

// isHTML reports whether a Content-Type names an HTML document.
func isHTML(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	switch ct {
	case "text/html", "application/xhtml+xml", "application/xml", "text/xml":
		return true
	}
	// Servers frequently omit or mislabel Content-Type; treat a missing one as
	// HTML so the seed page is still parsed.
	return ct == ""
}

// baseDomain reduces a hostname to its registrable domain, using a small table
// of multi-part public suffixes so example.co.uk keeps three labels. An IP
// literal is returned unchanged.
func baseDomain(host string) string {
	host = netutil.NormalizeHost(host)
	if host == "" || net.ParseIP(host) != nil {
		return host
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	if multiPartSuffixes[strings.Join(labels[len(labels)-2:], ".")] && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// multiPartSuffixes is a pragmatic list of common two-label public suffixes.
// It only needs to cover cases a recon tool is likely to meet; a wrong guess
// simply widens the base domain by one label without ever crossing registries.
var multiPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "net.uk": true, "sch.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true, "ac.nz": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"com.tr": true, "net.tr": true, "org.tr": true, "gov.tr": true, "edu.tr": true,
	"co.in": true, "net.in": true, "org.in": true, "gov.in": true, "ac.in": true,
	"co.za": true, "org.za": true, "net.za": true, "gov.za": true,
	"com.mx": true, "com.ar": true, "com.sg": true, "com.hk": true, "com.tw": true,
	"co.kr": true, "or.kr": true, "co.id": true, "co.il": true, "co.ke": true,
}

// filenameFromURL returns the last path segment, or the host when the path is
// empty.
func filenameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	name := path.Base(u.Path)
	if name == "/" || name == "." || name == "" {
		name = u.Hostname()
	}
	return name
}

// assetExt returns the file extension to store an asset under, preferring the
// URL's extension and falling back to one derived from the MIME type.
func assetExtName(rawURL, contentType string) string {
	if ext := strings.ToLower(path.Ext(mustPath(rawURL))); ext != "" && len(ext) <= 6 {
		return ext
	}
	switch mimeFrom(contentType, rawURL) {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "image/svg+xml":
		return ".svg"
	case "image/x-icon", "image/vnd.microsoft.icon":
		return ".ico"
	case "text/css":
		return ".css"
	case "application/javascript", "text/javascript":
		return ".js"
	case "application/pdf":
		return ".pdf"
	case "application/json":
		return ".json"
	case "text/plain":
		return ".txt"
	}
	return ""
}

func extFrom(rawURL, contentType string) string {
	return assetExtName(rawURL, contentType)
}

func mustPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}

// mimeFrom returns the response's MIME type, or one inferred from the URL.
func mimeFrom(contentType, rawURL string) string {
	if ct := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]); ct != "" {
		return strings.ToLower(ct)
	}
	switch strings.ToLower(path.Ext(mustPath(rawURL))) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".pdf":
		return "application/pdf"
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mp3":
		return "audio/mpeg"
	}
	return "application/octet-stream"
}

// assetKind classifies an asset for the media browser.
func assetKind(contentType, rawURL string) string {
	mime := mimeFrom(contentType, rawURL)
	switch {
	case strings.HasPrefix(mime, "image/"):
		return "image"
	case strings.HasPrefix(mime, "video/"):
		return "video"
	case strings.HasPrefix(mime, "audio/"):
		return "audio"
	case strings.HasPrefix(mime, "font/"), strings.Contains(mime, "font"):
		return "font"
	case mime == "text/css":
		return "stylesheet"
	case mime == "application/javascript", mime == "text/javascript":
		return "script"
	case mime == "application/pdf", mime == "application/zip", mime == "application/msword":
		return "document"
	}
	switch strings.ToLower(path.Ext(mustPath(rawURL))) {
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		return "font"
	case ".css":
		return "stylesheet"
	case ".js":
		return "script"
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".gz":
		return "document"
	case ".mp4", ".webm", ".mov", ".avi", ".mkv":
		return "video"
	case ".mp3", ".ogg", ".wav", ".m4a", ".flac":
		return "audio"
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif":
		return "image"
	}
	return "other"
}

// marshalMeta encodes the document's meta pairs for display in the preview.
func marshalMeta(meta []metaPair) string {
	if len(meta) == 0 {
		return "[]"
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// humanBytes renders a byte count with a binary unit suffix.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

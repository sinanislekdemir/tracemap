// Package webcrawl fetches a domain's frontpage and one level of same-site
// links, along with robots.txt and sitemap.xml, using a browser-like
// User-Agent. It is pure Go (net/http plus golang.org/x/net/html) and never
// shells out to an external tool.
package webcrawl

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver is the subset of net.Resolver used to turn discovered hostnames
// into addresses, so it can be faked in tests. net.Resolver satisfies it.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Options controls a crawl. The zero value is usable: Discover fills in
// sensible defaults.
type Options struct {
	// Domain is the apex domain to crawl. Required.
	Domain string
	// MaxPages caps how many documents are fetched (frontpage plus level 1).
	MaxPages int
	// MaxBodyBytes caps the stored body of a single response.
	MaxBodyBytes int64
	// Timeout bounds a single HTTP request.
	Timeout time.Duration
	// Concurrency limits parallel level-1 fetches.
	Concurrency int
	// UserAgent is sent with every request; defaults to DefaultUserAgent.
	UserAgent string
	// BaseURL overrides the starting URL (used by tests). When empty the
	// crawler tries https://<domain>/ then http://<domain>/.
	BaseURL string
	// Client overrides the HTTP client (used by tests).
	Client *http.Client
	// Resolver resolves discovered subdomains; defaults to net.DefaultResolver.
	Resolver Resolver
	// OnPage is called for every page as soon as it is parsed.
	OnPage func(Page)
	// OnProgress is called after every fetched page.
	OnProgress func(done, total, found int)
	// OnLog reports each fetch attempt and its outcome, so callers can show
	// what the crawl tried. level is one of "info", "ok", "warn", "error".
	OnLog func(level, message string)
}

// Page is one fetched document. HTML holds the raw response body for text-like
// content, capped at MaxBodyBytes.
type Page struct {
	URL         string   `json:"url"`
	Depth       int      `json:"depth"`
	Status      int      `json:"status"`
	ContentType string   `json:"contentType,omitempty"`
	Title       string   `json:"title,omitempty"`
	Size        int      `json:"size"`
	Truncated   bool     `json:"truncated,omitempty"`
	HTML        string   `json:"html,omitempty"`
	Links       []string `json:"links,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
}

// Robots is the parsed robots.txt.
type Robots struct {
	URL      string   `json:"url"`
	Status   int      `json:"status"`
	Body     string   `json:"body,omitempty"`
	Sitemaps []string `json:"sitemaps,omitempty"`
	Paths    []string `json:"paths,omitempty"`
}

// Sitemap is one parsed sitemap or sitemap index document.
type Sitemap struct {
	URL    string   `json:"url"`
	Status int      `json:"status"`
	URLs   []string `json:"urls,omitempty"`
	Nested []string `json:"nested,omitempty"`
}

// Subdomain is a discovered in-domain hostname and its resolved addresses.
type Subdomain struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

// Result is the outcome of a crawl.
type Result struct {
	Pages      []Page      `json:"pages"`
	Robots     *Robots     `json:"robots,omitempty"`
	Sitemaps   []Sitemap   `json:"sitemaps,omitempty"`
	Subdomains []Subdomain `json:"subdomains,omitempty"`
	URLs       []string    `json:"urls,omitempty"`
}

const (
	defaultMaxPages    = 25
	defaultMaxBody     = int64(2 << 20)
	defaultTimeout     = 10 * time.Second
	defaultConcurrency = 4
	maxRedirects       = 10
	maxSitemaps        = 10
	maxSitemapDepth    = 2

	// DefaultUserAgent is a current desktop Chrome string, so sites that vary
	// their response by client serve the crawler the regular page.
	DefaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

// crawler holds the mutable state of a single crawl.
type crawler struct {
	domain   string
	opts     Options
	client   *http.Client
	resolver Resolver

	// siteHost is the host the frontpage finally resolved to after redirects;
	// same-site crawling follows it even when it differs from the apex.
	siteHost string

	mu       sync.Mutex
	pages    []Page
	fetched  map[string]bool
	urls     map[string]bool
	hosts    map[string]bool
	sitemaps []Sitemap
	robots   *Robots
	total    int
	done     int64
}

// Crawl fetches domain's frontpage and one level of same-site links, parses
// robots.txt and sitemap.xml, and returns every in-domain subdomain it saw.
func Crawl(ctx context.Context, domain string, opts Options) Result {
	domain = normalizeHost(domain)
	opts = withDefaults(opts)

	c := &crawler{
		domain:   domain,
		opts:     opts,
		client:   opts.Client,
		resolver: opts.Resolver,
		fetched:  make(map[string]bool),
		urls:     make(map[string]bool),
		hosts:    make(map[string]bool),
	}
	if c.client == nil {
		c.client = &http.Client{
			Timeout: opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				return nil
			},
		}
	}
	if c.resolver == nil {
		c.resolver = net.DefaultResolver
	}

	c.logf("info", "crawl start · %s · max %d pages · %d workers · timeout %s",
		domain, opts.MaxPages, opts.Concurrency, opts.Timeout)

	page := c.frontpage(ctx)
	if page == nil {
		c.logf("error", "frontpage unreachable; nothing to crawl")
		return c.result(ctx)
	}
	base, err := url.Parse(page.URL)
	if err != nil {
		base = nil
	} else {
		c.siteHost = normalizeHost(base.Hostname())
		c.logf("ok", "frontpage · %s · %d links", c.siteHost, len(page.Links))
	}

	c.crawlRobots(ctx, base)
	c.crawlSitemaps(ctx, base)

	candidates := c.level1Candidates(page, base)
	c.logf("info", "%d same-site candidate(s) for level 1", len(candidates))
	if len(candidates) == 0 {
		c.logf("warn", "no level-1 candidates (frontpage had no same-site links, sitemap or robots paths)")
	}
	c.setTotal(1 + len(candidates))
	c.emitProgress()
	c.fetchAll(ctx, candidates, 1)
	c.logf("info", "crawl finished · %d pages fetched", len(c.pages))

	return c.result(ctx)
}

// frontpage fetches the domain root, trying https before http unless a base
// URL was supplied. When the apex has no www and the base candidates fail, the
// www host is tried too; IP addresses never get a www fallback. It returns nil
// when nothing responds.
func (c *crawler) frontpage(ctx context.Context) *Page {
	candidates := make([]string, 0, 4)
	if c.opts.BaseURL != "" {
		candidates = append(candidates, c.opts.BaseURL)
	} else {
		candidates = append(candidates,
			"https://"+c.domain+"/", "http://"+c.domain+"/")
		if www := wwwHost(c.domain); www != "" {
			candidates = append(candidates,
				"https://"+www+"/", "http://"+www+"/")
		}
	}
	for _, raw := range candidates {
		c.logf("info", "GET %s", raw)
		resp, err := c.fetch(ctx, raw)
		if err != nil {
			c.logf("warn", "  ✗ %v", err)
			continue
		}
		page := c.toPage(resp, 0)
		c.addPage(page)
		if page.Title != "" {
			c.logf("ok", "  → %d %s · %q · %d B", resp.Status, resp.URL, page.Title, len(resp.Body))
		} else {
			c.logf("ok", "  → %d %s · %s · %d B", resp.Status, resp.URL, contentTypeLabel(resp.ContentType), len(resp.Body))
		}
		return &page
	}
	c.logf("error", "frontpage: all %d candidate(s) failed", len(candidates))
	return nil
}

// wwwHost returns "www."+domain for a non-IP domain that does not already start
// with www, or "" when the www fallback does not apply.
func wwwHost(domain string) string {
	if domain == "" || strings.HasPrefix(domain, "www.") {
		return ""
	}
	if net.ParseIP(domain) != nil {
		return ""
	}
	return "www." + domain
}

// crawlRobots fetches and parses robots.txt for the base host.
func (c *crawler) crawlRobots(ctx context.Context, base *url.URL) {
	if base == nil {
		return
	}
	raw := base.Scheme + "://" + base.Host + "/robots.txt"
	c.logf("info", "GET %s", raw)
	resp, err := c.fetch(ctx, raw)
	if err != nil {
		c.logf("warn", "  ✗ robots.txt: %v", err)
		return
	}
	robots := &Robots{URL: resp.URL, Status: resp.Status, Body: string(resp.Body)}
	robots.Sitemaps, robots.Paths = parseRobots(robots.Body)

	c.mu.Lock()
	c.robots = robots
	c.mu.Unlock()

	c.logf("ok", "  → robots.txt %d · %d sitemaps · %d paths", resp.Status, len(robots.Sitemaps), len(robots.Paths))
	for _, sitemap := range robots.Sitemaps {
		c.logf("info", "    sitemap directive → %s", sitemap)
		c.addURL(sitemap)
	}
	for _, path := range robots.Paths {
		c.logf("info", "    path → %s", path)
	}
}

// crawlSitemaps fetches the sitemaps named by robots.txt (or the conventional
// /sitemap.xml), following sitemap indexes to a bounded depth.
func (c *crawler) crawlSitemaps(ctx context.Context, base *url.URL) {
	seeds := make([]string, 0, 2)
	c.mu.Lock()
	if c.robots != nil {
		seeds = append(seeds, c.robots.Sitemaps...)
	}
	c.mu.Unlock()
	if len(seeds) == 0 && base != nil {
		seeds = append(seeds, base.Scheme+"://"+base.Host+"/sitemap.xml")
	}

	type job struct {
		url   string
		depth int
	}
	queue := make([]job, 0, len(seeds))
	for _, seed := range seeds {
		queue = append(queue, job{url: seed})
	}
	seen := make(map[string]bool)
	count := 0
	for len(queue) > 0 && count < maxSitemaps {
		current := queue[0]
		queue = queue[1:]
		if current.url == "" || seen[current.url] || current.depth > maxSitemapDepth {
			continue
		}
		seen[current.url] = true

		c.logf("info", "GET %s", current.url)
		resp, err := c.fetch(ctx, current.url)
		if err != nil {
			c.logf("warn", "  ✗ sitemap: %v", err)
			continue
		}
		count++
		urls, nested := parseSitemap(resp.Body)
		if len(urls) == 0 && len(nested) == 0 {
			c.logf("warn", "  → sitemap %d · no entries", resp.Status)
			continue
		}
		c.logf("ok", "  → sitemap %d · %d urls · %d nested", resp.Status, len(urls), len(nested))
		c.mu.Lock()
		c.sitemaps = append(c.sitemaps, Sitemap{
			URL: resp.URL, Status: resp.Status, URLs: urls, Nested: nested,
		})
		c.mu.Unlock()

		for _, u := range urls {
			c.addURL(u)
		}
		for _, n := range nested {
			queue = append(queue, job{url: n, depth: current.depth + 1})
		}
	}
}

// level1Candidates builds the deduplicated, same-site set of pages to fetch at
// depth 1: frontpage links, sitemap URLs and robots.txt paths.
func (c *crawler) level1Candidates(page *Page, base *url.URL) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(page.Links))
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		if !c.sameSite(normalizeHost(u.Hostname())) {
			return
		}
		if seen[raw] {
			return
		}
		seen[raw] = true
		out = append(out, raw)
	}

	for _, link := range page.Links {
		add(link)
	}

	c.mu.Lock()
	for _, sitemap := range c.sitemaps {
		for _, u := range sitemap.URLs {
			add(u)
		}
	}
	var paths []string
	if c.robots != nil {
		paths = append(paths, c.robots.Paths...)
	}
	c.mu.Unlock()

	for _, path := range paths {
		if strings.ContainsAny(path, "*$") {
			continue
		}
		add(resolvePath(base, path))
	}

	max := c.opts.MaxPages - 1
	if max < 0 {
		max = 0
	}
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// sameSite reports whether host belongs to the scanned site: the apex domain,
// any of its subdomains, or the host the frontpage redirected to.
func (c *crawler) sameSite(host string) bool {
	if host == "" {
		return false
	}
	if isSameSite(host, c.domain) {
		return true
	}
	if c.siteHost != "" && (host == c.siteHost || isStrictSubdomain(host, c.siteHost)) {
		return true
	}
	return false
}

// fetchAll fetches urls at the given depth with bounded concurrency.
func (c *crawler) fetchAll(ctx context.Context, urls []string, depth int) {
	sem := make(chan struct{}, c.opts.Concurrency)
	var wg sync.WaitGroup
	for _, raw := range urls {
		if ctx.Err() != nil {
			break
		}
		c.mu.Lock()
		skip := c.fetched[raw]
		c.mu.Unlock()
		if skip {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(raw string) {
			defer wg.Done()
			defer func() { <-sem }()
			c.logf("info", "GET %s", raw)
			resp, err := c.fetch(ctx, raw)
			if err != nil {
				c.logf("warn", "  ✗ %v", err)
				return
			}
			page := c.toPage(resp, depth)
			c.addPage(page)
			if page.Title != "" {
				c.logf("ok", "  → %d %s · %q · %d B", resp.Status, resp.URL, page.Title, len(resp.Body))
			} else {
				c.logf("ok", "  → %d %s · %s · %d B", resp.Status, resp.URL, contentTypeLabel(resp.ContentType), len(resp.Body))
			}
		}(raw)
	}
	wg.Wait()
}

// response is a fetched HTTP response with a capped body.
type response struct {
	URL         string
	Status      int
	ContentType string
	Body        []byte
	Truncated   bool
}

// fetch performs a single GET with the browser User-Agent and a capped read.
func (c *crawler) fetch(ctx context.Context, rawurl string) (response, error) {
	parsed, err := url.Parse(rawurl)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return response{}, fmt.Errorf("unsupported url %q", rawurl)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := c.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxBodyBytes+1))
	if err != nil {
		return response{}, err
	}
	truncated := int64(len(body)) > c.opts.MaxBodyBytes
	if truncated {
		body = body[:c.opts.MaxBodyBytes]
	}

	final := parsed.String()
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return response{
		URL:         final,
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		Truncated:   truncated,
	}, nil
}

// toPage converts a response into a Page, parsing links and recording every
// hostname it sees.
func (c *crawler) toPage(resp response, depth int) Page {
	page := Page{
		URL:         resp.URL,
		Depth:       depth,
		Status:      resp.Status,
		ContentType: resp.ContentType,
		Size:        len(resp.Body),
		Truncated:   resp.Truncated,
	}
	if !isHTML(resp.ContentType) {
		if isText(resp.ContentType) {
			page.HTML = string(resp.Body)
		}
		return page
	}

	base, err := url.Parse(resp.URL)
	if err != nil {
		return page
	}
	title, links := pageLinks(resp.Body, base)
	page.Title = title
	page.HTML = string(resp.Body)
	page.Links = links

	hosts := make(map[string]bool)
	for _, link := range links {
		if u, err := url.Parse(link); err == nil {
			if host := normalizeHost(u.Hostname()); host != "" {
				hosts[host] = true
			}
		}
		c.addURL(link)
	}
	page.Hosts = keys(hosts)
	return page
}

// addURL records a discovered URL and any in-domain hostname it names.
func (c *crawler) addURL(raw string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return
	}
	c.mu.Lock()
	c.urls[raw] = true
	if isStrictSubdomain(host, c.domain) {
		c.hosts[host] = true
	}
	c.mu.Unlock()
}

// addPage appends a page once, keyed by its final URL, and reports progress.
func (c *crawler) addPage(page Page) {
	c.mu.Lock()
	if c.fetched[page.URL] {
		c.mu.Unlock()
		return
	}
	c.fetched[page.URL] = true
	c.pages = append(c.pages, page)
	c.mu.Unlock()

	if c.opts.OnPage != nil {
		c.opts.OnPage(page)
	}
	atomic.AddInt64(&c.done, 1)
	c.emitProgress()
}

// setTotal records how many pages this crawl expects to fetch.
func (c *crawler) setTotal(total int) {
	c.mu.Lock()
	c.total = total
	c.mu.Unlock()
}

// emitProgress reports fetch progress to the caller.
func (c *crawler) emitProgress() {
	if c.opts.OnProgress == nil {
		return
	}
	c.mu.Lock()
	total := c.total
	found := len(c.hosts)
	c.mu.Unlock()
	c.opts.OnProgress(int(atomic.LoadInt64(&c.done)), total, found)
}

// logf reports a verbose crawl step to the caller.
func (c *crawler) logf(level, format string, args ...any) {
	if c.opts.OnLog == nil {
		return
	}
	c.opts.OnLog(level, fmt.Sprintf(format, args...))
}

// result assembles the final, deterministically ordered Result and resolves
// every discovered subdomain.
func (c *crawler) result(ctx context.Context) Result {
	c.mu.Lock()
	pages := append([]Page(nil), c.pages...)
	robots := c.robots
	sitemaps := append([]Sitemap(nil), c.sitemaps...)
	urls := keys(c.urls)
	hosts := keys(c.hosts)
	c.mu.Unlock()

	sort.Slice(pages, func(i, j int) bool { return pages[i].URL < pages[j].URL })

	subdomains := make([]Subdomain, 0, len(hosts))
	for _, host := range hosts {
		subdomains = append(subdomains, Subdomain{Name: host, IPs: c.resolve(ctx, host)})
	}
	return Result{
		Pages:      pages,
		Robots:     robots,
		Sitemaps:   sitemaps,
		Subdomains: subdomains,
		URLs:       urls,
	}
}

// resolve turns a hostname into sorted IP strings.
func (c *crawler) resolve(ctx context.Context, host string) []string {
	ips, err := c.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

// withDefaults fills unset options with their defaults.
func withDefaults(opts Options) Options {
	if opts.MaxPages <= 0 {
		opts.MaxPages = defaultMaxPages
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBody
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	return opts
}

// resolvePath turns a robots.txt path into an absolute URL on base.
func resolvePath(base *url.URL, path string) string {
	if base == nil || path == "" {
		return ""
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base.Scheme + "://" + base.Host + path
}

// keys returns the sorted keys of a set.
func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Package httputil holds HTTP helpers shared by the crawling, domain-analysis
// and origin-discovery paths.
package httputil

// User-Agent strings offered by the scrape tool. Sites that vary their response
// by client serve the automated request the corresponding page.
const (
	// ChromeUserAgent is a current desktop Chrome string.
	ChromeUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	// FirefoxUserAgent is a current desktop Firefox string.
	FirefoxUserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
	// EdgeUserAgent is a current desktop Edge string.
	EdgeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
	// CurlUserAgent is the default curl string, for when a plain client is
	// wanted (or to probe how a site treats non-browser clients).
	CurlUserAgent = "curl/8.6.0"
)

// BrowserUserAgent is the default User-Agent (a desktop Chrome string) used
// unless a caller overrides it.
const BrowserUserAgent = ChromeUserAgent

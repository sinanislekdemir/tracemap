// Package httputil holds HTTP helpers shared by the crawling, domain-analysis
// and origin-discovery paths.
package httputil

// BrowserUserAgent is a current desktop Chrome string, so sites that vary their
// response by client serve the automated request the regular page.
const BrowserUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

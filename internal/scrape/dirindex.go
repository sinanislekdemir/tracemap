package scrape

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// directoryURLs returns the directory URLs to test for an open listing, given a
// page URL: the page's own directory followed by each ancestor up to the root.
// "https://h/something/another/my.html" yields
// ["https://h/something/another/", "https://h/something/", "https://h/"].
// Query and fragment are dropped. Non-http(s) URLs yield nothing.
func directoryURLs(rawURL string) []string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	dir := path
	if !strings.HasSuffix(dir, "/") {
		if i := strings.LastIndex(dir, "/"); i >= 0 {
			dir = dir[:i+1]
		} else {
			dir = "/"
		}
	}

	out := make([]string, 0, 4)
	for {
		du := *u
		du.Path = dir
		du.RawQuery = ""
		du.Fragment = ""
		out = append(out, du.String())
		if dir == "/" {
			break
		}
		trimmed := strings.TrimSuffix(dir, "/")
		i := strings.LastIndex(trimmed, "/")
		if i < 0 {
			dir = "/"
		} else {
			dir = trimmed[:i+1]
		}
	}
	return out
}

// analyzeIndex reports whether an HTML response looks like a directory listing
// (an accidental "Index of /…" / "Directory listing" page), returning the
// document title and the number of links it exposes. Detection keys on the
// document's title/heading so ordinary pages that merely mention "index of" are
// not false positives.
func analyzeIndex(body []byte) (title string, entries int, leak bool) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", 0, false
	}
	var h1 string
	var anchors int
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "title":
				if title == "" {
					title = strings.TrimSpace(nodeText(n))
				}
			case "h1":
				if h1 == "" {
					h1 = strings.TrimSpace(nodeText(n))
				}
			case "a":
				anchors++
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	signal := strings.ToLower(title + " " + h1)
	if strings.Contains(signal, "index of") || strings.Contains(signal, "directory listing") {
		return title, anchors, true
	}
	return title, 0, false
}

// sameDirectory reports whether a response's final URL still addresses the same
// directory that was probed, so a redirect to an unrelated page (for example a
// site homepage that happens to be an index) is not misattributed.
func sameDirectory(finalURL, probedURL string) bool {
	a, err1 := url.Parse(finalURL)
	b, err2 := url.Parse(probedURL)
	if err1 != nil || err2 != nil {
		return false
	}
	if !strings.EqualFold(a.Host, b.Host) {
		return false
	}
	return strings.TrimSuffix(a.Path, "/") == strings.TrimSuffix(b.Path, "/")
}

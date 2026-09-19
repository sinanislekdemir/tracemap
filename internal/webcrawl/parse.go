package webcrawl

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// pageLinks parses an HTML document and returns its title plus every absolute
// http(s) link it references. Relative links are resolved against base.
func pageLinks(body []byte, base *url.URL) (string, []string) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", nil
	}

	seen := make(map[string]bool)
	links := make([]string, 0, 32)
	var title string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			return
		}
		value := abs.String()
		if seen[value] {
			return
		}
		seen[value] = true
		links = append(links, value)
	}

	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "title":
				if title == "" {
					title = strings.TrimSpace(nodeText(node))
				}
			case "a":
				add(attr(node, "href"))
			case "link":
				add(attr(node, "href"))
			case "script":
				add(attr(node, "src"))
			case "img":
				add(attr(node, "src"))
			case "iframe":
				add(attr(node, "src"))
			case "form":
				add(attr(node, "action"))
			case "meta":
				if strings.EqualFold(attr(node, "http-equiv"), "refresh") {
					add(refreshURL(attr(node, "content")))
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	return title, links
}

// attr returns the value of an element attribute, case-insensitively.
func attr(node *html.Node, key string) string {
	for _, a := range node.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// nodeText concatenates the text nodes under node.
func nodeText(node *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return b.String()
}

// refreshURL extracts the target of a meta-refresh content value such as
// "0; url=/next".
func refreshURL(content string) string {
	lower := strings.ToLower(content)
	index := strings.Index(lower, "url=")
	if index < 0 {
		return ""
	}
	value := strings.TrimSpace(content[index+len("url="):])
	value = strings.Trim(value, `"'`)
	return value
}

// parseRobots extracts Sitemap directives and Allow/Disallow paths from a
// robots.txt body.
func parseRobots(body string) (sitemaps, paths []string) {
	for _, raw := range strings.Split(body, "\n") {
		line := raw
		if hash := strings.IndexByte(line, '#'); hash >= 0 {
			line = line[:hash]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "sitemap":
			if value != "" {
				sitemaps = append(sitemaps, value)
			}
		case "allow", "disallow":
			if value != "" {
				paths = append(paths, value)
			}
		}
	}
	return sitemaps, paths
}

// sitemapLoc holds the <loc> of a sitemap or url entry.
type sitemapLoc struct {
	Loc string `xml:"loc"`
}

// parseSitemap returns the page URLs and nested sitemap URLs named by a sitemap
// or sitemap-index document. Gzip-compressed bodies are transparently decoded.
func parseSitemap(body []byte) (urls, nested []string) {
	data := body
	if len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, nil
		}
		defer reader.Close()
		decoded, err := io.ReadAll(io.LimitReader(reader, defaultMaxBody))
		if err != nil {
			return nil, nil
		}
		data = decoded
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "sitemap":
			var entry sitemapLoc
			if err := decoder.DecodeElement(&entry, &start); err == nil {
				if loc := strings.TrimSpace(entry.Loc); loc != "" {
					nested = append(nested, loc)
				}
			}
		case "url":
			var entry sitemapLoc
			if err := decoder.DecodeElement(&entry, &start); err == nil {
				if loc := strings.TrimSpace(entry.Loc); loc != "" {
					urls = append(urls, loc)
				}
			}
		}
	}
	return urls, nested
}

// contentTypeLabel shortens a Content-Type header for logs.
func contentTypeLabel(contentType string) string {
	if contentType == "" {
		return "unknown type"
	}
	if semi := strings.IndexByte(contentType, ';'); semi >= 0 {
		contentType = contentType[:semi]
	}
	return strings.TrimSpace(contentType)
}

// isHTML reports whether a content type is an HTML document.
func isHTML(contentType string) bool {
	lower := strings.ToLower(contentType)
	return strings.Contains(lower, "text/html") || strings.Contains(lower, "application/xhtml")
}

// isText reports whether a content type is worth storing as text.
func isText(contentType string) bool {
	if contentType == "" {
		return true
	}
	lower := strings.ToLower(contentType)
	for _, marker := range []string{"text/", "xml", "json", "javascript", "x-httpd-php"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases a hostname and strips a trailing root dot.
func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// isStrictSubdomain reports whether name is a proper subdomain of domain.
func isStrictSubdomain(name, domain string) bool {
	if name == "" || domain == "" || name == domain {
		return false
	}
	return strings.HasSuffix(name, "."+domain)
}

// isSameSite reports whether host is the domain or one of its subdomains.
func isSameSite(host, domain string) bool {
	return host == domain || isStrictSubdomain(host, domain)
}

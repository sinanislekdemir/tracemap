package scrape

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"traceroute/internal/netutil"
)

// metaPair is one <meta> entry, kept for display and for the flattened search
// text. Key is the meta name or property.
type metaPair struct {
	Key   string
	Value string
}

// parsedDoc is the result of parsing one HTML document: metadata, visible text,
// in-document links and subresource URLs (already resolved to absolute URLs
// against the response's final URL).
type parsedDoc struct {
	Title       string
	Description string
	Keywords    string
	Lang        string
	Canonical   string
	Meta        []metaPair
	MetaText    string
	Text        string
	Links       []string
	Images      []string
	Resources   []string
}

// parseHTML walks an HTML document and extracts metadata, visible text, links
// and subresources. base is the document's final URL, used to resolve relative
// references. A parse failure yields a zero-value document.
func parseHTML(body []byte, base *url.URL) parsedDoc {
	var doc parsedDoc
	root, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return doc
	}

	var text strings.Builder
	var walk func(n *html.Node, skip bool)
	walk = func(n *html.Node, skip bool) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "script":
				doc.Resources = appendRef(doc.Resources, base, attr(n, "src"))
				skip = true
			case "style", "noscript", "template":
				skip = true
			case "html":
				if doc.Lang == "" {
					doc.Lang = strings.TrimSpace(attr(n, "lang"))
				}
			case "title":
				if doc.Title == "" {
					doc.Title = strings.TrimSpace(nodeText(n))
				}
			case "meta":
				handleMeta(n, &doc)
			case "link":
				handleLink(n, base, &doc)
			case "a":
				if href := resolveRef(base, attr(n, "href")); href != "" {
					doc.Links = append(doc.Links, href)
				}
			case "img":
				doc.Images = appendRef(doc.Images, base, attr(n, "src"))
				doc.Images = appendSrcset(doc.Images, base, attr(n, "srcset"))
			case "source":
				doc.Resources = appendRef(doc.Resources, base, attr(n, "src"))
				doc.Images = appendSrcset(doc.Images, base, attr(n, "srcset"))
			case "video", "audio", "track":
				doc.Resources = appendRef(doc.Resources, base, attr(n, "src"))
			case "object":
				doc.Resources = appendRef(doc.Resources, base, attr(n, "data"))
			case "embed":
				doc.Resources = appendRef(doc.Resources, base, attr(n, "src"))
			}
		}
		if n.Type == html.TextNode && !skip {
			if t := strings.TrimSpace(n.Data); t != "" {
				text.WriteString(t)
				text.WriteByte(' ')
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, skip)
		}
	}
	walk(root, false)

	doc.Text = strings.Join(strings.Fields(text.String()), " ")
	doc.Links = netutil.Dedupe(doc.Links)
	doc.Images = netutil.Dedupe(doc.Images)
	doc.Resources = netutil.Dedupe(doc.Resources)
	doc.MetaText = buildMetaText(doc)
	return doc
}

// handleMeta records a <meta> tag's name/property and content, promoting the
// description and keywords to their own fields.
func handleMeta(n *html.Node, doc *parsedDoc) {
	key := strings.TrimSpace(attr(n, "name"))
	if key == "" {
		key = strings.TrimSpace(attr(n, "property"))
	}
	content := strings.TrimSpace(attr(n, "content"))
	if key == "" || content == "" {
		return
	}
	switch strings.ToLower(key) {
	case "description":
		if doc.Description == "" {
			doc.Description = content
		}
	case "keywords":
		if doc.Keywords == "" {
			doc.Keywords = content
		}
	}
	doc.Meta = append(doc.Meta, metaPair{Key: key, Value: content})
}

// handleLink classifies a <link> by its rel: stylesheets and preloads are
// subresources, icons are images and canonical records the canonical URL.
func handleLink(n *html.Node, base *url.URL, doc *parsedDoc) {
	rel := strings.ToLower(strings.TrimSpace(attr(n, "rel")))
	href := resolveRef(base, attr(n, "href"))
	if rel == "" || href == "" {
		return
	}
	switch {
	case strings.Contains(rel, "stylesheet"):
		doc.Resources = append(doc.Resources, href)
	case strings.Contains(rel, "icon"):
		doc.Images = append(doc.Images, href)
	case strings.Contains(rel, "preload"):
		if strings.EqualFold(strings.TrimSpace(attr(n, "as")), "image") {
			doc.Images = append(doc.Images, href)
		} else {
			doc.Resources = append(doc.Resources, href)
		}
	case strings.Contains(rel, "canonical"):
		if doc.Canonical == "" {
			doc.Canonical = href
		}
	}
}

// buildMetaText flattens the document's metadata into "key: value" lines, the
// text indexed by the metadata search field.
func buildMetaText(doc parsedDoc) string {
	var b strings.Builder
	add := func(key, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		b.WriteString(key)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	add("title", doc.Title)
	add("description", doc.Description)
	add("keywords", doc.Keywords)
	add("language", doc.Lang)
	add("canonical", doc.Canonical)
	for _, m := range doc.Meta {
		switch strings.ToLower(m.Key) {
		case "description", "keywords":
			continue
		}
		add(m.Key, m.Value)
	}
	return b.String()
}

// appendRef resolves ref against base and appends it when it is a usable
// http(s) URL.
func appendRef(out []string, base *url.URL, ref string) []string {
	if resolved := resolveRef(base, ref); resolved != "" {
		return append(out, resolved)
	}
	return out
}

// appendSrcset parses a srcset attribute and appends every candidate URL.
func appendSrcset(out []string, base *url.URL, srcset string) []string {
	for _, cand := range strings.Split(srcset, ",") {
		fields := strings.Fields(strings.TrimSpace(cand))
		if len(fields) == 0 {
			continue
		}
		out = appendRef(out, base, fields[0])
	}
	return out
}

// resolveRef turns a possibly-relative reference into an absolute http(s) URL,
// dropping fragments and non-fetchable schemes (data:, mailto:, javascript:,
// tel:). An empty or unusable reference yields "".
func resolveRef(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return ""
	}
	lower := strings.ToLower(ref)
	switch {
	case strings.HasPrefix(lower, "javascript:"),
		strings.HasPrefix(lower, "mailto:"),
		strings.HasPrefix(lower, "data:"),
		strings.HasPrefix(lower, "tel:"),
		strings.HasPrefix(lower, "blob:"):
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

// matchKeywords returns the keywords found (case-insensitively) in text. With
// KeywordMatch "all", the result is empty unless every non-empty keyword
// matched. An empty keyword list disables filtering and returns nil.
func matchKeywords(text string, keywords []string, mode KeywordMatch) []string {
	total := 0
	for _, kw := range keywords {
		if strings.TrimSpace(kw) != "" {
			total++
		}
	}
	if total == 0 {
		return nil
	}
	lower := strings.ToLower(text)
	matched := make([]string, 0, total)
	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(kw)) {
			matched = append(matched, kw)
		}
	}
	if mode == MatchAll && len(matched) < total {
		return nil
	}
	return matched
}

// attr returns the value of the first attribute with the given key.
func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// nodeText concatenates the direct text children of a node.
func nodeText(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	}
	return b.String()
}

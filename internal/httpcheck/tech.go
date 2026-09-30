package httpcheck

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// serverProducts are the server products recognised in a Server banner.
var serverProducts = []string{
	"nginx", "apache", "microsoft-iis", "iis", "cloudflare", "envoy", "traefik",
	"caddy", "gunicorn", "uvicorn", "werkzeug", "jetty", "tomcat", "openresty",
	"lighttpd", "litespeed", "h2o", "amazon s3", "github.com", "google frontend",
	"gse", "varnish", "haproxy", "istio", "kestrel", "cow", "node.js", "openstar",
}

// bodyMarkers are substrings in HTML that reveal a framework, CMS or CDN.
var bodyMarkers = []struct {
	needle   string
	name     string
	category string
}{
	{"/_next/", "Next.js", "framework"},
	{"__next_data__", "Next.js", "framework"},
	{"/_nuxt/", "Nuxt", "framework"},
	{"__nuxt__", "Nuxt", "framework"},
	{"wp-content", "WordPress", "cms"},
	{"wp-includes", "WordPress", "cms"},
	{"data-reactroot", "React", "framework"},
	{"ng-version", "Angular", "framework"},
	{"ng-app", "Angular", "framework"},
	{"cdn.shopify.com", "Shopify", "cms"},
	{"static.parastorage.com", "Wix", "cms"},
	{"sites.google.com", "Google Sites", "cms"},
	{"jsdelivr.net", "jsDelivr CDN", "cdn"},
	{"unpkg.com", "unpkg CDN", "cdn"},
	{"cdnjs.cloudflare.com", "cdnjs CDN", "cdn"},
}

// detectTech fingerprints the stack from headers, cookies, body and TLS.
func detectTech(header http.Header, cookies []Cookie, body []byte, state tls.ConnectionState) []Tech {
	found := make(map[string]Tech)
	add := func(name, category, evidence string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := name + "|" + category
		if _, ok := found[key]; !ok {
			found[key] = Tech{Name: name, Category: category, Evidence: evidence}
		}
	}

	if server := header.Get("Server"); server != "" {
		add(serverProduct(server), "server", "Server: "+server)
	}
	for _, name := range []string{
		"x-powered-by", "x-generator", "x-aspnet-version", "x-aspnetmvc-version",
		"x-shopify-stage", "x-jenkins", "x-confluence", "x-drupal-cache", "x-runtime",
	} {
		if value := header.Get(name); value != "" {
			add(value, "framework", name+": "+value)
		}
	}
	if value := header.Get("x-varnish"); value != "" {
		add("Varnish", "cache", "x-varnish: "+value)
	}
	if value := header.Get("via"); value != "" {
		add("Proxy", "proxy", "Via: "+value)
	}

	for _, cookie := range cookies {
		if cookie.Tech != "" {
			add(cookie.Tech, "cookie", "Set-Cookie: "+cookie.Name)
		}
	}

	for _, marker := range detectBodyTech(body) {
		add(marker.Name, marker.Category, marker.Evidence)
	}

	if state.NegotiatedProtocol == "h2" {
		add("HTTP/2", "protocol", "ALPN negotiated h2")
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		issuer := cert.Issuer.CommonName
		if issuer == "" && len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		}
		add(issuer, "certificate", "TLS certificate issuer")
	}

	out := make([]Tech, 0, len(found))
	for _, tech := range found {
		out = append(out, tech)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// serverProduct extracts a friendly product name from a Server banner.
func serverProduct(server string) string {
	lower := strings.ToLower(server)
	for _, product := range serverProducts {
		if strings.Contains(lower, product) {
			switch product {
			case "iis", "microsoft-iis":
				return "Microsoft IIS"
			case "cloudflare":
				return "Cloudflare"
			case "amazon s3":
				return "Amazon S3"
			case "github.com":
				return "GitHub Pages"
			case "google frontend", "gse":
				return "Google Frontend"
			case "node.js":
				return "Node.js"
			}
			return titleCase(product)
		}
	}
	if token, _, _ := strings.Cut(strings.TrimSpace(server), " "); token != "" {
		return token
	}
	return "unknown server"
}

// titleCase upper-cases the first rune of an ASCII product name.
func titleCase(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

// detectBodyTech scans an HTML/text body for framework markers and meta
// generator tags.
func detectBodyTech(body []byte) []Tech {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	found := make(map[string]Tech)
	add := func(name, category, evidence string) {
		key := name + "|" + category
		if _, ok := found[key]; !ok {
			found[key] = Tech{Name: name, Category: category, Evidence: evidence}
		}
	}
	for _, marker := range bodyMarkers {
		if bytes.Contains(lower, []byte(marker.needle)) {
			add(marker.name, marker.category, "body contains "+marker.needle)
		}
	}
	for _, generator := range metaGenerators(body) {
		add(generator, "generator", `meta generator: "`+generator+`"`)
	}

	out := make([]Tech, 0, len(found))
	for _, tech := range found {
		out = append(out, tech)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// metaGenerators returns the content of every <meta name="generator"> tag.
func metaGenerators(body []byte) []string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	var out []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "meta") {
			if strings.EqualFold(htmlAttr(node, "name"), "generator") {
				if content := strings.TrimSpace(htmlAttr(node, "content")); content != "" {
					out = append(out, content)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return out
}

// htmlAttr returns an element attribute value, case-insensitively.
func htmlAttr(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}

// buildTechChecks records each detected technology as an informational check.
func buildTechChecks(report *Report, add func(id, category, title, status, detail string)) {
	for _, tech := range report.Tech {
		add("tech-"+tech.Category+"-"+tech.Name, CategoryTech, tech.Name, StatusInfo,
			tech.Category+" · "+tech.Evidence)
	}
}

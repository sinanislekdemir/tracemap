package origin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Rules are the intermediary markers used to recognise a proxy response. They
// are configurable so the marker set can be maintained in a file instead of a
// code change. An empty Rules (both slices nil) means the built-in defaults.
type Rules struct {
	// HeaderNames are exact response header names an intermediary adds.
	HeaderNames []string `json:"headerNames"`
	// HeaderPrefixes match intermediary header names by prefix.
	HeaderPrefixes []string `json:"headerPrefixes"`
}

// defaultProxyHeaderNames are the built-in exact intermediary header names.
// The standard entries are generic caching/routing headers; the rest are
// stable, protocol-level CDN marker header NAMES (not IP ranges), which need no
// maintenance and survive infrastructure changes.
var defaultProxyHeaderNames = []string{
	"via",
	"forwarded",
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-proto",
	"x-cache",
	"x-cache-hits",
	"age",
	"x-served-by",
	"x-cdn",
	"cf-ray",
	"cf-cache-status",
	"x-amz-cf-id",
	"x-amz-cf-pop",
	"x-sucuri-id",
	"x-iinfo",
}

// defaultProxyHeaderPrefixes are the built-in intermediary header prefixes.
var defaultProxyHeaderPrefixes = []string{"cdn-", "x-akamai-"}

// DefaultRules returns a copy of the built-in intermediary markers.
func DefaultRules() Rules {
	return Rules{
		HeaderNames:    append([]string(nil), defaultProxyHeaderNames...),
		HeaderPrefixes: append([]string(nil), defaultProxyHeaderPrefixes...),
	}
}

// LoadRules reads a rules file. A missing or empty path returns the defaults.
// A malformed file returns the defaults together with the parse error.
func LoadRules(path string) (Rules, error) {
	if strings.TrimSpace(path) == "" {
		return DefaultRules(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultRules(), nil
		}
		return DefaultRules(), err
	}
	rules := DefaultRules()
	if err := json.Unmarshal(data, &rules); err != nil {
		return DefaultRules(), err
	}
	return rules.normalized(), nil
}

// SaveRules writes rules as indented JSON, creating the parent directory.
func SaveRules(path string, rules Rules) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rules.normalized(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// normalized lower-cases, trims, dedupes and sorts the marker lists.
func (r Rules) normalized() Rules {
	r.HeaderNames = cleanList(r.HeaderNames)
	r.HeaderPrefixes = cleanList(r.HeaderPrefixes)
	return r
}

func cleanList(values []string) []string {
	if values == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// Package netutil holds small network and hostname helpers shared across the
// traceroute packages: hostname normalization, address resolution, private-IP
// classification and slice deduplication. It deliberately depends on nothing
// but the standard library so every feature package can use it.
package netutil

import (
	"context"
	"net"
	"sort"
	"strings"
)

// Resolver is the subset of net.Resolver used to turn a host into addresses.
// net.Resolver satisfies it, as do the per-package Resolver interfaces that
// embed LookupIP.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// NormalizeHost lowercases a hostname and strips surrounding whitespace and a
// trailing root dot. It does not strip a port; use NormalizeDomain for input
// that may carry one.
func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// NormalizeDomain reduces free-form user input to a bare hostname: it trims
// whitespace, lowercases, drops a scheme (everything up to "://"), drops a
// path, query or fragment, removes a :port suffix and strips a trailing root
// dot. IPv6 literals must be bracketed ("[::1]:443") for their port to be
// removed; an unbracketed literal is returned unchanged.
func NormalizeDomain(input string) string {
	domain := strings.TrimSpace(strings.ToLower(input))
	if i := strings.Index(domain, "://"); i >= 0 {
		domain = domain[i+3:]
	}
	if i := strings.IndexAny(domain, "/?#"); i >= 0 {
		domain = domain[:i]
	}
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	return strings.TrimSuffix(domain, ".")
}

// ResolveIPs resolves host to its address strings, returning nil on error.
func ResolveIPs(ctx context.Context, resolver Resolver, host string) []string {
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// IsPublicIP reports whether ip is a routable address suitable for geolocation
// or external probing. Non-IP input is not public.
func IsPublicIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !(parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() ||
		parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsMulticast())
}

// IsStrictSubdomain reports whether name is a proper subdomain of domain.
func IsStrictSubdomain(name, domain string) bool {
	if name == "" || domain == "" || name == domain {
		return false
	}
	return strings.HasSuffix(name, "."+domain)
}

// IsSameSite reports whether host is the domain or one of its subdomains.
func IsSameSite(host, domain string) bool {
	return host == domain || IsStrictSubdomain(host, domain)
}

// Dedupe returns the non-empty, whitespace-trimmed values with duplicates
// removed, preserving first-seen order.
func Dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// MergeUnique returns a new slice holding the non-empty values of base followed
// by the non-empty values of extra that are not already present, preserving
// first-seen order. base is never mutated.
func MergeUnique(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, value := range base {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, value := range extra {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// SortedKeys returns the keys of a string-keyed set in ascending order.
func SortedKeys[V any](set map[string]V) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Cap returns at most limit elements of values. A non-positive limit returns
// values unchanged.
func Cap[T any](values []T, limit int) []T {
	if limit > 0 && len(values) > limit {
		return values[:limit]
	}
	return values
}

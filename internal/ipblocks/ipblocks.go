// Package ipblocks enumerates the IPv4 and IPv6 network blocks stored in a
// local GeoLite2 database, grouped by country. It powers the "Country IP
// blocks" tool.
//
// A full walk of the MaxMind search tree decodes every network record (a few
// million on a current GeoLite2-City database) in a couple of seconds, so the
// work is done on demand and cached: the per-country summary is computed once,
// and the block list for the country currently being browsed is cached until
// ClearCache is called.
package ipblocks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const (
	countryDBName = "GeoLite2-Country.mmdb"
	cityDBName    = "GeoLite2-City.mmdb"
)

// defaultDirs are the conventional locations for MaxMind databases, shared
// with the geolocator.
var defaultDirs = []string{
	"/usr/share/GeoIP",
	"/usr/local/share/GeoIP",
	"/var/lib/GeoIP",
	"/opt/GeoIP",
}

// ProgressFunc reports walk progress: done of total networks (total is the
// search-tree node count, an upper-bound estimate).
type ProgressFunc func(done, total int)

// Metadata describes the opened database.
type Metadata struct {
	Path      string
	Database  string
	BuildTime time.Time
	IPVersion int
	NodeCount uint
}

// Country is one row of the per-country block summary.
type Country struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Blocks    int    `json:"blocks"`
	Addresses string `json:"addresses"`

	// addrSum accumulates the address space during the walk (float64 is exact
	// enough for a human-readable magnitude).
	addrSum float64
}

// countryRecord is the subset of a GeoLite2 record needed to group blocks.
type countryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// Paging defaults for a block query.
const (
	DefaultLimit = 5000
	MaxLimit     = 50000
)

// Query selects one page of a country's blocks.
type Query struct {
	// Family is "" (both), "ipv4" or "ipv6".
	Family string
	// Filter is a case-insensitive substring matched against the CIDR text.
	Filter string
	// Limit caps the returned block strings; the first Limit matches are kept.
	Limit int
}

// Page is a filtered, bounded slice of a country's blocks.
type Page struct {
	Total     int
	Matched   int
	Addresses string
	Blocks    []string
	Truncated bool
}

// DB is an opened country/city database.
type DB struct {
	reader *maxminddb.Reader
	meta   Metadata

	mu        sync.Mutex
	countries []Country
	loaded    bool
	cacheKey  string
	cache     []netip.Prefix
}

// Open locates and opens the best local database for country blocks: an
// explicit GeoLite2-Country database when present, otherwise GeoLite2-City.
func Open() (*DB, error) {
	path := findDB()
	if path == "" {
		return nil, errors.New("no local GeoLite2 Country or City database found")
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	info := reader.Metadata
	build := time.Time{}
	if info.BuildEpoch > 0 {
		build = time.Unix(int64(info.BuildEpoch), 0)
	}
	return &DB{
		reader: reader,
		meta: Metadata{
			Path:      path,
			Database:  info.DatabaseType,
			BuildTime: build,
			IPVersion: int(info.IPVersion),
			NodeCount: info.NodeCount,
		},
	}, nil
}

// findDB resolves the database path from an explicit environment override, the
// TRACEROUTE_GEOIP_DIR override, or the conventional GeoIP directories. A
// Country database wins over a City database.
func findDB() string {
	if path := os.Getenv("TRACEROUTE_GEOIP_COUNTRY_DB"); path != "" {
		return path
	}
	if path := os.Getenv("TRACEROUTE_GEOIP_CITY_DB"); path != "" {
		return path
	}
	dirs := defaultDirs
	if dir := os.Getenv("TRACEROUTE_GEOIP_DIR"); dir != "" {
		dirs = append([]string{dir}, dirs...)
	}
	for _, name := range []string{countryDBName, cityDBName} {
		for _, dir := range dirs {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	return ""
}

// Metadata returns the opened database's description.
func (d *DB) Metadata() Metadata { return d.meta }

// Path returns the opened database's path.
func (d *DB) Path() string { return d.meta.Path }

// Close releases the database handle.
func (d *DB) Close() error {
	if d.reader == nil {
		return nil
	}
	return d.reader.Close()
}

// ClearCache drops the cached country block list, releasing its memory.
func (d *DB) ClearCache() {
	d.mu.Lock()
	d.cache = nil
	d.cacheKey = ""
	d.mu.Unlock()
}

// Countries walks the database and returns every country that owns at least one
// network, sorted by descending block count. The result is cached after the
// first call.
func (d *DB) Countries(ctx context.Context, onProgress ProgressFunc) ([]Country, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.loaded {
		return d.countries, nil
	}

	counts := make(map[string]*Country)
	total := int(d.meta.NodeCount)
	done := 0

	nets := d.reader.Networks(maxminddb.SkipAliasedNetworks)
	var rec countryRecord
	for nets.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ipnet, err := nets.Network(&rec)
		if err != nil {
			return nil, err
		}
		code := rec.Country.ISOCode
		country := counts[code]
		if country == nil {
			name := rec.Country.Names["en"]
			if name == "" && code == "" {
				name = "Unknown"
			}
			country = &Country{Code: code, Name: name}
			counts[code] = country
		}
		country.Blocks++
		country.addrSum += prefixAddressCount(ipnet)

		done++
		if onProgress != nil && done%20000 == 0 {
			onProgress(done, total)
		}
	}
	if err := nets.Err(); err != nil {
		return nil, err
	}

	out := make([]Country, 0, len(counts))
	for _, country := range counts {
		country.Addresses = humanCount(country.addrSum)
		out = append(out, *country)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Blocks != out[j].Blocks {
			return out[i].Blocks > out[j].Blocks
		}
		return out[i].Code < out[j].Code
	})

	d.countries = out
	d.loaded = true
	return out, nil
}

// Blocks walks the database and returns every network owned by country, in
// ascending address order. The result is cached for the country currently being
// browsed; selecting another country replaces the cache.
func (d *DB) Blocks(ctx context.Context, country string, onProgress ProgressFunc) ([]netip.Prefix, error) {
	country = strings.ToUpper(strings.TrimSpace(country))

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cacheKey == country {
		return d.cache, nil
	}

	var out []netip.Prefix
	total := int(d.meta.NodeCount)
	done := 0

	nets := d.reader.Networks(maxminddb.SkipAliasedNetworks)
	var rec countryRecord
	for nets.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ipnet, err := nets.Network(&rec)
		if err != nil {
			return nil, err
		}
		done++
		if rec.Country.ISOCode == country {
			if prefix, ok := toPrefix(ipnet); ok {
				out = append(out, prefix)
			}
		}
		if onProgress != nil && done%20000 == 0 {
			onProgress(done, total)
		}
	}
	if err := nets.Err(); err != nil {
		return nil, err
	}

	d.cacheKey = country
	d.cache = out
	return out, nil
}

// Query loads a country's blocks (cached) and returns one filtered page.
func (d *DB) Query(ctx context.Context, country string, q Query, onProgress ProgressFunc) (Page, error) {
	prefixes, err := d.Blocks(ctx, country, onProgress)
	if err != nil {
		return Page{}, err
	}
	return Paginate(prefixes, q), nil
}

// Paginate applies a family filter, a substring filter and a limit to a full
// country block list, summing the address space of every match.
func Paginate(prefixes []netip.Prefix, q Query) Page {
	family := strings.ToLower(strings.TrimSpace(q.Family))
	filter := strings.ToLower(strings.TrimSpace(q.Filter))
	limit := q.Limit
	switch {
	case limit == 0:
		limit = DefaultLimit
	case limit < 0:
		// A negative limit means "every match" (used by exports).
		limit = int(^uint(0) >> 1)
	case limit > MaxLimit:
		limit = MaxLimit
	}

	page := Page{Total: len(prefixes)}
	var sum float64
	for _, prefix := range prefixes {
		if !familyMatches(prefix, family) {
			continue
		}
		text := prefix.String()
		if filter != "" && !strings.Contains(strings.ToLower(text), filter) {
			continue
		}
		page.Matched++
		sum += addrCount(prefix.Bits(), prefix.Addr().BitLen())
		if len(page.Blocks) < limit {
			page.Blocks = append(page.Blocks, text)
		}
	}
	page.Truncated = page.Matched > len(page.Blocks)
	page.Addresses = humanCount(sum)
	return page
}

// familyMatches reports whether a prefix belongs to the requested family.
func familyMatches(prefix netip.Prefix, family string) bool {
	switch family {
	case "", "all", "any":
		return true
	case "ipv4", "v4":
		return prefix.Addr().Is4()
	case "ipv6", "v6":
		return prefix.Addr().Is6() && !prefix.Addr().Is4In6()
	default:
		return true
	}
}

// toPrefix converts a decoded network to a netip.Prefix, preserving its
// address family.
func toPrefix(ipnet *net.IPNet) (netip.Prefix, bool) {
	if ipnet == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := ipnet.Mask.Size()
	if ones < 0 || ones > addr.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones), true
}

// prefixAddressCount is the number of addresses a decoded network covers.
func prefixAddressCount(ipnet *net.IPNet) float64 {
	if ipnet == nil {
		return 0
	}
	ones, bits := ipnet.Mask.Size()
	return addrCount(ones, bits)
}

// addrCount is 2^(bits-ones), the size of a network, as a float.
func addrCount(ones, bits int) float64 {
	if bits == 0 || ones < 0 {
		return 0
	}
	if ones > bits {
		ones = bits
	}
	return math.Pow(2, float64(bits-ones))
}

// humanCount renders an address-space magnitude, e.g. 1.2B or 3.4M.
func humanCount(value float64) string {
	switch {
	case value >= 1e15:
		return strconv.FormatFloat(value/1e15, 'f', 2, 64) + "P"
	case value >= 1e12:
		return strconv.FormatFloat(value/1e12, 'f', 2, 64) + "T"
	case value >= 1e9:
		return strconv.FormatFloat(value/1e9, 'f', 2, 64) + "B"
	case value >= 1e6:
		return strconv.FormatFloat(value/1e6, 'f', 2, 64) + "M"
	case value >= 1e3:
		return strconv.FormatFloat(value/1e3, 'f', 2, 64) + "K"
	default:
		return strconv.FormatFloat(value, 'f', 0, 64)
	}
}

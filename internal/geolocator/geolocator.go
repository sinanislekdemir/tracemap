package geolocator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"traceroute/internal/appdata"
)

// GeoData is the resolved geographic information for an IP address.
type GeoData struct {
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	City     string  `json:"city"`
	Country  string  `json:"country"`
	ASN      string  `json:"asn"`
	Resolved bool    `json:"resolved"`
}

// LookupFunc resolves a single IP to GeoData via a remote service.
type LookupFunc func(ctx context.Context, ip string) (GeoData, error)

// LocalLookup resolves a single IP from a local database. ok=false means the
// address is absent, and the caller should fall back to the remote lookup.
type LocalLookup func(ip string) (GeoData, bool)

// Resolver resolves IP addresses to geographic locations. A lookup is served
// from the in-memory cache, then the persistent SQLite cache, then the remote
// service (ipwho.is, the source of truth), and finally a local GeoLite2
// database. Remote queries are rate limited.
type Resolver struct {
	cache   map[string]GeoData
	mu      sync.RWMutex
	client  *http.Client
	lookup  LookupFunc
	local   LocalLookup
	store   *geoStore
	limiter *rateLimiter
	closers []io.Closer
}

// NewResolver creates a Resolver backed by the public ipwho.is service, a
// persistent cache, and any local GeoLite2 databases that are installed.
func NewResolver() *Resolver {
	r := newResolver(nil, nil)

	if local := openLocal(); local != nil {
		r.local = local.lookup
		r.closers = append(r.closers, local)
	}

	store, err := openStore(appdata.DefaultPath())
	switch {
	case err != nil:
		log.Printf("geolocator: cache unavailable: %v", err)
	case store != nil:
		r.store = store
		r.closers = append(r.closers, store)
		log.Printf("geolocator: cache %s", store.path)
	}

	return r
}

// NewResolverWithLookup creates a Resolver with a custom remote lookup function
// and no local database, primarily useful for tests.
func NewResolverWithLookup(lookup LookupFunc) *Resolver {
	return newResolver(lookup, nil)
}

func newResolver(lookup LookupFunc, local LocalLookup) *Resolver {
	r := &Resolver{
		cache:   make(map[string]GeoData),
		client:  &http.Client{Timeout: 5 * time.Second},
		local:   local,
		limiter: newRateLimiter(defaultRatePerSecond),
	}
	if lookup != nil {
		r.lookup = lookup
	} else {
		r.lookup = r.lookupHTTP
	}
	return r
}

// Close releases the cache and any local database handles.
func (r *Resolver) Close() error {
	var errs []error
	for _, closer := range r.closers {
		errs = append(errs, closer.Close())
	}
	return errors.Join(errs...)
}

// ResolveOne returns the geo-location for a single IP. Private, loopback and
// otherwise non-routable addresses are reported as unresolved without a lookup.
func (r *Resolver) ResolveOne(ctx context.Context, ip string) (GeoData, error) {
	if !isPublicIP(ip) {
		return GeoData{City: "Private network"}, nil
	}

	r.mu.RLock()
	cached, found := r.cache[ip]
	r.mu.RUnlock()
	if found {
		return cached, nil
	}

	// Persistent cache: entries originate from the remote service.
	if r.store != nil {
		if data, ok := r.store.get(ctx, ip); ok {
			r.remember(ip, data)
			return data, nil
		}
	}

	// The remote service is the source of truth.
	data, err := r.resolveRemote(ctx, ip)
	if err == nil {
		r.remember(ip, data)
		if r.store != nil {
			r.store.put(ctx, ip, data)
		}
		return data, nil
	}
	if ctx.Err() != nil {
		return GeoData{}, err
	}

	// Fall back to a local database when the remote lookup fails.
	if r.local != nil {
		if local, ok := r.local(ip); ok {
			r.remember(ip, local)
			return local, nil
		}
	}

	return GeoData{}, err
}

// resolveRemote applies the rate limit before querying the remote service.
func (r *Resolver) resolveRemote(ctx context.Context, ip string) (GeoData, error) {
	if err := r.limiter.wait(ctx); err != nil {
		return GeoData{}, err
	}
	return r.lookup(ctx, ip)
}

func (r *Resolver) remember(ip string, data GeoData) {
	r.mu.Lock()
	r.cache[ip] = data
	r.mu.Unlock()
}

// ResolveParallel resolves multiple IPs concurrently, preserving input order.
// Individual lookup failures are returned in the corresponding slot with
// Resolved set to false and do not fail the whole batch.
func (r *Resolver) ResolveParallel(ctx context.Context, ips []string) []GeoData {
	results := make([]GeoData, len(ips))
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, address string) {
			defer wg.Done()
			data, err := r.ResolveOne(ctx, address)
			if err != nil {
				data = GeoData{}
			}
			results[index] = data
		}(i, ip)
	}

	wg.Wait()
	return results
}

// lookupHTTP queries the ipwho.is API for a single IP.
func (r *Resolver) lookupHTTP(ctx context.Context, ip string) (GeoData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/"+ip, nil)
	if err != nil {
		return GeoData{}, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return GeoData{}, fmt.Errorf("geo lookup for %s: %w", ip, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GeoData{}, fmt.Errorf("geo lookup for %s: unexpected status %s", ip, resp.Status)
	}

	var payload struct {
		Success     bool    `json:"success"`
		Message     string  `json:"message"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		City        string  `json:"city"`
		CountryCode string  `json:"country_code"`
		Connection  struct {
			ASN int    `json:"asn"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return GeoData{}, fmt.Errorf("geo lookup for %s: %w", ip, err)
	}
	if !payload.Success {
		msg := payload.Message
		if msg == "" {
			msg = "lookup failed"
		}
		return GeoData{}, fmt.Errorf("geo lookup for %s: %s", ip, msg)
	}

	asn := payload.Connection.ISP
	if payload.Connection.ASN != 0 {
		asn = fmt.Sprintf("AS%d", payload.Connection.ASN)
		if payload.Connection.ISP != "" {
			asn = fmt.Sprintf("AS%d %s", payload.Connection.ASN, payload.Connection.ISP)
		}
	}

	return GeoData{
		Lat:      payload.Latitude,
		Lon:      payload.Longitude,
		City:     payload.City,
		Country:  payload.CountryCode,
		ASN:      asn,
		Resolved: true,
	}, nil
}

// isPublicIP reports whether ip is a routable address suitable for geolocation.
func isPublicIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() ||
		parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() ||
		parsed.IsMulticast() {
		return false
	}
	return true
}

// Local GeoLite2 database support. The databases are optional: when none is
// found the resolver falls back to the remote service.

const (
	cityDBName = "GeoLite2-City.mmdb"
	asnDBName  = "GeoLite2-ASN.mmdb"
)

// defaultGeoIPDirs are the conventional locations for MaxMind databases.
var defaultGeoIPDirs = []string{
	"/usr/share/GeoIP",
	"/usr/local/share/GeoIP",
	"/var/lib/GeoIP",
	"/opt/GeoIP",
}

// mmdbResolver reads from a GeoLite2 City and/or ASN database.
type mmdbResolver struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// openLocal opens whichever GeoLite2 databases can be located. It returns nil
// when neither is available.
func openLocal() *mmdbResolver {
	cityPath := findDB("TRACEROUTE_GEOIP_CITY_DB", cityDBName)
	asnPath := findDB("TRACEROUTE_GEOIP_ASN_DB", asnDBName)

	var city, asn *maxminddb.Reader
	if cityPath != "" {
		reader, err := maxminddb.Open(cityPath)
		if err != nil {
			log.Printf("geolocator: cannot open %s: %v", cityPath, err)
		} else {
			city = reader
			log.Printf("geolocator: city database %s", cityPath)
		}
	}
	if asnPath != "" {
		reader, err := maxminddb.Open(asnPath)
		if err != nil {
			log.Printf("geolocator: cannot open %s: %v", asnPath, err)
		} else {
			asn = reader
			log.Printf("geolocator: ASN database %s", asnPath)
		}
	}

	if city == nil && asn == nil {
		return nil
	}
	return &mmdbResolver{city: city, asn: asn}
}

// findDB resolves a database path from an explicit environment override, the
// TRACEROUTE_GEOIP_DIR override, or the conventional GeoIP directories.
func findDB(envVar, name string) string {
	if path := os.Getenv(envVar); path != "" {
		return path
	}
	dirs := defaultGeoIPDirs
	if dir := os.Getenv("TRACEROUTE_GEOIP_DIR"); dir != "" {
		dirs = append([]string{dir}, dirs...)
	}
	for _, dir := range dirs {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// lookup resolves an IP from the local databases, reporting whether either
// database contained the address.
func (m *mmdbResolver) lookup(ip string) (GeoData, bool) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return GeoData{}, false
	}

	data := GeoData{}
	found := false

	if m.city != nil {
		var record struct {
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			Location struct {
				Latitude  float64 `maxminddb:"latitude"`
				Longitude float64 `maxminddb:"longitude"`
			} `maxminddb:"location"`
		}
		if _, ok, err := m.city.LookupNetwork(addr, &record); err == nil && ok {
			data.Lat = record.Location.Latitude
			data.Lon = record.Location.Longitude
			data.City = record.City.Names["en"]
			data.Country = record.Country.ISOCode
			found = true
		}
	}

	if m.asn != nil {
		var record struct {
			Number uint   `maxminddb:"autonomous_system_number"`
			Org    string `maxminddb:"autonomous_system_organization"`
		}
		if _, ok, err := m.asn.LookupNetwork(addr, &record); err == nil && ok {
			switch {
			case record.Number != 0 && record.Org != "":
				data.ASN = fmt.Sprintf("AS%d %s", record.Number, record.Org)
			case record.Number != 0:
				data.ASN = fmt.Sprintf("AS%d", record.Number)
			default:
				data.ASN = record.Org
			}
			found = true
		}
	}

	if !found {
		return GeoData{}, false
	}
	// A country- or ASN-only database carries no coordinates; defer to the
	// remote lookup so the hop can still be placed on the map.
	if data.Lat == 0 && data.Lon == 0 {
		return GeoData{}, false
	}
	data.Resolved = true
	return data, true
}

// Close releases the underlying database handles.
func (m *mmdbResolver) Close() error {
	var errs []error
	if m.city != nil {
		errs = append(errs, m.city.Close())
	}
	if m.asn != nil {
		errs = append(errs, m.asn.Close())
	}
	return errors.Join(errs...)
}

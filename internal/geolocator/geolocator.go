package geolocator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
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
// database. Remote queries are rate limited, retried on transient failures, and
// short-circuited by a circuit breaker so an outage degrades to the local
// database instead of stalling every hop.
type Resolver struct {
	cache   map[string]GeoData
	mu      sync.RWMutex
	client  *http.Client
	lookup  LookupFunc
	local   LocalLookup
	store   *geoStore
	limiter *rateLimiter
	closers []io.Closer

	attemptTimeout time.Duration
	maxAttempts    int
	parallelism    int
	breaker        *circuitBreaker
}

// Remote lookup resilience defaults. A single attempt is capped by
// attemptTimeout, and the number of attempts by maxAttempts, so a hung service
// can never stall a lookup for long before the local fallback runs. The rate
// limiter is intentional pacing and is not counted against either bound.
const (
	defaultAttemptTimeout = 3 * time.Second
	defaultMaxAttempts    = 2
	defaultParallelism    = 16
	breakerFailureLimit   = 3
	breakerCooldown       = 30 * time.Second
)

// errRemoteUnavailable is returned when the circuit breaker is open and no
// local database could resolve the address.
var errRemoteUnavailable = errors.New("geolocator: remote lookup unavailable")

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
		cache:          make(map[string]GeoData),
		client:         &http.Client{Timeout: 4 * time.Second},
		local:          local,
		limiter:        newRateLimiter(defaultRatePerSecond),
		attemptTimeout: defaultAttemptTimeout,
		maxAttempts:    defaultMaxAttempts,
		parallelism:    defaultParallelism,
		breaker:        newCircuitBreaker(breakerFailureLimit, breakerCooldown),
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

	// The remote service is the source of truth. Consult it unless the caller
	// has already given up or the breaker is temporarily open.
	var remoteErr error
	if ctx.Err() == nil && r.breaker.allow() {
		data, err := r.resolveRemote(ctx, ip)
		if err == nil {
			r.breaker.record(true)
			r.remember(ip, data)
			if r.store != nil {
				// Persist even if the caller's deadline fires right after the
				// reply arrived, so the lookup is not repeated.
				r.store.put(context.WithoutCancel(ctx), ip, data)
			}
			return data, nil
		}
		// A non-retryable error still means the service answered, so the
		// breaker is only tripped by transient failures.
		r.breaker.record(!retryable(err))
		remoteErr = err
	} else if ctx.Err() != nil {
		remoteErr = ctx.Err()
	} else {
		remoteErr = errRemoteUnavailable
	}

	// A user cancellation is final. A deadline still leaves room for a fast,
	// context-free local fallback.
	if errors.Is(ctx.Err(), context.Canceled) {
		return GeoData{}, remoteErr
	}

	// Fall back to a local database when the remote lookup is unavailable.
	if r.local != nil {
		if local, ok := r.local(ip); ok {
			r.remember(ip, local)
			return local, nil
		}
	}

	return GeoData{}, remoteErr
}

// resolveRemote queries the remote service, retrying transient failures and
// applying the rate limit before every attempt.
func (r *Resolver) resolveRemote(ctx context.Context, ip string) (GeoData, error) {
	attempts := r.maxAttempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			if err := sleepCtx(ctx, retryDelay(attempt-1)); err != nil {
				return GeoData{}, lastErr
			}
		}
		if err := r.limiter.wait(ctx); err != nil {
			if lastErr != nil {
				return GeoData{}, lastErr
			}
			return GeoData{}, err
		}

		data, err := r.lookupAttempt(ctx, ip)
		if err == nil {
			return data, nil
		}
		lastErr = err

		// Stop as soon as the caller is done, regardless of the error class.
		if ctx.Err() != nil {
			return GeoData{}, ctx.Err()
		}
		if !retryable(err) {
			return GeoData{}, err
		}
	}
	return GeoData{}, lastErr
}

// lookupAttempt runs one remote lookup, capping the individual attempt so a
// hung call cannot stall the whole lookup.
func (r *Resolver) lookupAttempt(ctx context.Context, ip string) (GeoData, error) {
	if r.attemptTimeout <= 0 {
		return r.lookup(ctx, ip)
	}
	attemptCtx, cancel := context.WithTimeout(ctx, r.attemptTimeout)
	defer cancel()
	return r.lookup(attemptCtx, ip)
}

// retryDelay returns the jittered backoff before the given retry (1-based).
func retryDelay(retry int) time.Duration {
	const base = 150 * time.Millisecond
	const max = 2 * time.Second
	delay := base << (retry - 1)
	if delay <= 0 || delay > max {
		delay = max
	}
	return time.Duration(rand.Int63n(int64(delay)))
}

// sleepCtx waits for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// httpStatusError carries a non-2xx HTTP status from the remote service.
type httpStatusError struct {
	ip     string
	status string
	code   int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("geo lookup for %s: unexpected status %s", e.ip, e.status)
}

// apiError is a definitive negative reply from the remote service, such as an
// unknown address. Retrying cannot change the outcome.
type apiError struct {
	ip      string
	message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("geo lookup for %s: %s", e.ip, e.message)
}

// retryable reports whether a remote error may succeed on a later attempt.
// Transport failures, timeouts, rate limiting and 5xx responses are transient;
// context cancellation, API-level rejections and other 4xx responses are not.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		return false
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.code == http.StatusTooManyRequests || statusErr.code >= 500
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

// circuitBreaker short-circuits remote lookups after a run of transient
// failures. It is safe for concurrent use and lets a single probe through once
// the cooldown elapses (half-open) so recovery is detected without a thundering
// herd of simultaneous retries.
type circuitBreaker struct {
	mu        sync.Mutex
	limit     int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
	probing   bool
}

// newCircuitBreaker creates a breaker that opens after limit consecutive
// transient failures and stays open for cooldown.
func newCircuitBreaker(limit int, cooldown time.Duration) *circuitBreaker {
	return &circuitBreaker{limit: limit, cooldown: cooldown}
}

// allow reports whether a remote lookup may proceed.
func (b *circuitBreaker) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.openUntil.IsZero() {
		return true
	}
	if now.Before(b.openUntil) {
		return false
	}
	// Cooldown elapsed: admit one probe while the rest keep using the local
	// fallback.
	if b.probing {
		return false
	}
	b.probing = true
	return true
}

// record updates the breaker with the outcome of a remote attempt. healthy is
// true when the service answered (even with an API-level error) and false for
// transient failures. It always clears the half-open probe.
func (b *circuitBreaker) record(healthy bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
	if healthy {
		b.failures = 0
		b.openUntil = time.Time{}
		return
	}
	b.failures++
	if b.limit > 0 && b.failures >= b.limit {
		b.openUntil = time.Now().Add(b.cooldown)
		b.failures = 0
	}
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

	limit := r.parallelism
	if limit < 1 {
		limit = defaultParallelism
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, address string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[index] = GeoData{}
				return
			}
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
		return GeoData{}, &httpStatusError{ip: ip, status: resp.Status, code: resp.StatusCode}
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
		return GeoData{}, &apiError{ip: ip, message: msg}
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

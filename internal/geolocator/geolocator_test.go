package geolocator

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolveOneUsesCache(t *testing.T) {
	var calls int32
	resolver := NewResolverWithLookup(func(ctx context.Context, ip string) (GeoData, error) {
		atomic.AddInt32(&calls, 1)
		return GeoData{Lat: 1, Lon: 2, City: "Test", Country: "TC", ASN: "AS1", Resolved: true}, nil
	})

	first, err := resolver.ResolveOne(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveOne: %v", err)
	}
	second, err := resolver.ResolveOne(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveOne (cached): %v", err)
	}
	if first != second {
		t.Errorf("cached result differs: %+v vs %+v", first, second)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("lookup called %d times, want 1", got)
	}
}

func TestResolveOneSkipsPrivateIPs(t *testing.T) {
	var calls int32
	resolver := NewResolverWithLookup(func(ctx context.Context, ip string) (GeoData, error) {
		atomic.AddInt32(&calls, 1)
		return GeoData{}, nil
	})

	for _, ip := range []string{"192.168.1.1", "10.0.0.1", "127.0.0.1", "fe80::1"} {
		data, err := resolver.ResolveOne(context.Background(), ip)
		if err != nil {
			t.Fatalf("ResolveOne(%s): %v", ip, err)
		}
		if data.Resolved {
			t.Errorf("ResolveOne(%s) should not be resolved", ip)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("lookup called %d times for private IPs, want 0", got)
	}
}

func TestResolveParallelPreservesOrder(t *testing.T) {
	resolver := NewResolverWithLookup(func(ctx context.Context, ip string) (GeoData, error) {
		return GeoData{City: ip, Resolved: true}, nil
	})

	ips := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}
	results := resolver.ResolveParallel(context.Background(), ips)
	if len(results) != len(ips) {
		t.Fatalf("got %d results, want %d", len(results), len(ips))
	}
	for i, ip := range ips {
		if results[i].City != ip {
			t.Errorf("result %d = %q, want %q", i, results[i].City, ip)
		}
	}
}

func TestResolveOnePrefersRemote(t *testing.T) {
	var localCalls int32
	resolver := newResolver(
		func(ctx context.Context, ip string) (GeoData, error) {
			return GeoData{City: "remote", Resolved: true}, nil
		},
		func(ip string) (GeoData, bool) {
			atomic.AddInt32(&localCalls, 1)
			return GeoData{City: "local", Lat: 1, Lon: 2, Resolved: true}, true
		},
	)

	data, err := resolver.ResolveOne(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveOne: %v", err)
	}
	if data.City != "remote" {
		t.Errorf("city = %q, want remote", data.City)
	}
	if got := atomic.LoadInt32(&localCalls); got != 0 {
		t.Errorf("local lookup called %d times, want 0", got)
	}
}

func TestResolveOneFallsBackToLocal(t *testing.T) {
	resolver := newResolver(
		func(ctx context.Context, ip string) (GeoData, error) {
			return GeoData{}, errors.New("remote down")
		},
		func(ip string) (GeoData, bool) {
			return GeoData{City: "local", Lat: 1, Lon: 2, Resolved: true}, true
		},
	)

	data, err := resolver.ResolveOne(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveOne: %v", err)
	}
	if data.City != "local" {
		t.Errorf("city = %q, want local", data.City)
	}
}

func TestResolveOneReturnsRemoteErrorWithoutLocal(t *testing.T) {
	resolver := newResolver(
		func(ctx context.Context, ip string) (GeoData, error) {
			return GeoData{}, errors.New("remote down")
		},
		nil,
	)

	if _, err := resolver.ResolveOne(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("expected the remote error to surface")
	}
}

func TestResolveOneRetriesTransientError(t *testing.T) {
	var calls int32
	resolver := NewResolverWithLookup(func(ctx context.Context, ip string) (GeoData, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return GeoData{}, errors.New("temporary blip")
		}
		return GeoData{Lat: 1, Lon: 2, City: "ok", Resolved: true}, nil
	})
	resolver.attemptTimeout = 0

	data, err := resolver.ResolveOne(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveOne: %v", err)
	}
	if data.City != "ok" {
		t.Errorf("city = %q, want ok", data.City)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("lookup called %d times, want 2", got)
	}
}

func TestResolveOneDoesNotRetryPermanentError(t *testing.T) {
	var calls int32
	resolver := NewResolverWithLookup(func(ctx context.Context, ip string) (GeoData, error) {
		atomic.AddInt32(&calls, 1)
		return GeoData{}, &httpStatusError{ip: ip, status: "400 Bad Request", code: http.StatusBadRequest}
	})
	resolver.attemptTimeout = 0

	if _, err := resolver.ResolveOne(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("expected an error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("lookup called %d times, want 1", got)
	}
}

func TestResolveOneBreakerFallsBackToLocal(t *testing.T) {
	var remoteCalls, localCalls int32
	resolver := newResolver(
		func(ctx context.Context, ip string) (GeoData, error) {
			atomic.AddInt32(&remoteCalls, 1)
			return GeoData{}, errors.New("remote down")
		},
		func(ip string) (GeoData, bool) {
			atomic.AddInt32(&localCalls, 1)
			return GeoData{City: "local", Lat: 1, Lon: 2, Resolved: true}, true
		},
	)
	resolver.breaker = newCircuitBreaker(1, time.Minute)
	resolver.attemptTimeout = 0
	resolver.maxAttempts = 1

	if _, err := resolver.ResolveOne(context.Background(), "8.8.8.8"); err != nil {
		t.Fatalf("ResolveOne: %v", err)
	}
	before := atomic.LoadInt32(&remoteCalls)

	// The breaker is now open: the next lookup must skip the remote entirely.
	data, err := resolver.ResolveOne(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("ResolveOne (breaker open): %v", err)
	}
	if data.City != "local" {
		t.Errorf("city = %q, want local", data.City)
	}
	if got := atomic.LoadInt32(&remoteCalls); got != before {
		t.Errorf("remote calls = %d, want %d (breaker should be open)", got, before)
	}
	if got := atomic.LoadInt32(&localCalls); got != 2 {
		t.Errorf("local calls = %d, want 2", got)
	}
}

func TestResolveOneFallsBackOnDeadline(t *testing.T) {
	var localCalls int32
	resolver := newResolver(
		func(ctx context.Context, ip string) (GeoData, error) {
			<-ctx.Done()
			return GeoData{}, ctx.Err()
		},
		func(ip string) (GeoData, bool) {
			atomic.AddInt32(&localCalls, 1)
			return GeoData{City: "local", Lat: 1, Lon: 2, Resolved: true}, true
		},
	)
	resolver.attemptTimeout = 0
	resolver.maxAttempts = 1

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	data, err := resolver.ResolveOne(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveOne: %v", err)
	}
	if data.City != "local" {
		t.Errorf("city = %q, want local", data.City)
	}
	if got := atomic.LoadInt32(&localCalls); got != 1 {
		t.Errorf("local calls = %d, want 1", got)
	}
}

func TestResolveOneCancelledContextSkipsLocal(t *testing.T) {
	var localCalls int32
	resolver := newResolver(
		func(ctx context.Context, ip string) (GeoData, error) {
			return GeoData{}, errors.New("should not be called")
		},
		func(ip string) (GeoData, bool) {
			atomic.AddInt32(&localCalls, 1)
			return GeoData{City: "local", Resolved: true}, true
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := resolver.ResolveOne(ctx, "8.8.8.8"); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if got := atomic.LoadInt32(&localCalls); got != 0 {
		t.Errorf("local calls = %d, want 0", got)
	}
}

func TestCircuitBreakerHalfOpen(t *testing.T) {
	b := newCircuitBreaker(2, 30*time.Millisecond)
	if !b.allow() {
		t.Fatal("fresh breaker should allow")
	}
	b.record(false)
	if !b.allow() {
		t.Fatal("breaker should stay closed below the limit")
	}
	b.record(false)
	if b.allow() {
		t.Fatal("breaker should be open after reaching the limit")
	}

	time.Sleep(40 * time.Millisecond)
	if !b.allow() {
		t.Fatal("half-open breaker should admit one probe")
	}
	if b.allow() {
		t.Fatal("half-open breaker should admit only one probe")
	}
	b.record(true)
	if !b.allow() {
		t.Fatal("breaker should close after a successful probe")
	}
}

func TestRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transport", errors.New("connection refused"), true},
		{"timeout", context.DeadlineExceeded, true},
		{"cancelled", context.Canceled, false},
		{"429", &httpStatusError{code: http.StatusTooManyRequests}, true},
		{"500", &httpStatusError{code: http.StatusInternalServerError}, true},
		{"400", &httpStatusError{code: http.StatusBadRequest}, false},
		{"api rejection", &apiError{message: "invalid IP"}, false},
	}
	for _, tc := range cases {
		if got := retryable(tc.err); got != tc.want {
			t.Errorf("%s: retryable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestResolveOneUsesStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo.db")

	store1, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	remoteCalls := 0
	first := newResolver(func(ctx context.Context, ip string) (GeoData, error) {
		remoteCalls++
		return GeoData{Lat: 5, Lon: 6, City: "cached", Resolved: true}, nil
	}, nil)
	first.store = store1

	if _, err := first.ResolveOne(context.Background(), "8.8.8.8"); err != nil {
		t.Fatalf("ResolveOne: %v", err)
	}
	if remoteCalls != 1 {
		t.Fatalf("remote calls = %d, want 1", remoteCalls)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// A second resolver with a failing remote must be served from the store.
	store2, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer store2.Close()

	second := newResolver(func(ctx context.Context, ip string) (GeoData, error) {
		return GeoData{}, errors.New("remote down")
	}, nil)
	second.store = store2

	got, err := second.ResolveOne(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveOne (cached): %v", err)
	}
	if got.City != "cached" {
		t.Errorf("city = %q, want cached", got.City)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "geo.db"))
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	want := GeoData{Lat: 1.5, Lon: 2.5, City: "X", Country: "XC", ASN: "AS1", Resolved: true}
	store.put(ctx, "1.2.3.4", want)

	got, ok := store.get(ctx, "1.2.3.4")
	if !ok {
		t.Fatal("expected a cache hit")
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if _, ok := store.get(ctx, "5.6.7.8"); ok {
		t.Error("unexpected hit for a missing IP")
	}
}

func TestStoreExpiresOldEntries(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "geo.db"))
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer store.Close()

	old := time.Now().Add(-cacheTTL - time.Hour).Unix()
	if _, err := store.db.Exec(
		`INSERT INTO geo_cache (ip, lat, lon, city, country, asn, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"9.9.9.9", 1.0, 2.0, "", "", "", old); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, ok := store.get(context.Background(), "9.9.9.9"); ok {
		t.Error("expected the expired entry to miss")
	}
}

func TestStoreDisabledWhenPathEmpty(t *testing.T) {
	store, err := openStore("")
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	if store != nil {
		t.Error("expected a nil store for an empty path")
	}
}

func TestFindDBEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), cityDBName)
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	t.Setenv("TRACEROUTE_GEOIP_CITY_DB", path)
	if got := findDB("TRACEROUTE_GEOIP_CITY_DB", cityDBName); got != path {
		t.Errorf("findDB = %q, want %q", got, path)
	}
}

// TestLocalDatabaseLookup exercises a real installed GeoLite2 database when one
// is available, and is skipped otherwise.
func TestLocalDatabaseLookup(t *testing.T) {
	cityPath := findDB("TRACEROUTE_GEOIP_CITY_DB", cityDBName)
	if cityPath == "" {
		t.Skip("no GeoLite2 City database installed")
	}
	local := openLocal()
	if local == nil {
		t.Skip("no GeoLite2 database available")
	}
	defer local.Close()

	data, ok := local.lookup("8.8.8.8")
	if !ok {
		t.Skipf("database at %s has no coordinate data (country/ASN only)", cityPath)
	}
	if data.Lat == 0 && data.Lon == 0 {
		t.Error("expected coordinates from the City database")
	}
	t.Logf("8.8.8.8 -> %+v", data)
}

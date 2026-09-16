package geolocator

import (
	"context"
	"errors"
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

func TestRateLimiterSpacesCalls(t *testing.T) {
	limiter := newRateLimiter(20) // one call per 50ms

	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := limiter.wait(context.Background()); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("3 calls took %v, want at least 100ms", elapsed)
	}
}

func TestRateLimiterRespectsContext(t *testing.T) {
	limiter := newRateLimiter(1) // one call per second
	if err := limiter.wait(context.Background()); err != nil {
		t.Fatalf("first wait: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := limiter.wait(ctx); err == nil {
		t.Error("expected a context error")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	limiter := newRateLimiter(0)

	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := limiter.wait(context.Background()); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("disabled limiter took %v", elapsed)
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

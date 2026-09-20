package geolocator

import (
	"context"
	"database/sql"
	"time"

	"traceroute/internal/sqliteutil"
)

// cacheTTL is how long a cached reply is considered fresh. Geolocation data is
// fairly stable, so entries live for a month before being refreshed.
const cacheTTL = 30 * 24 * time.Hour

// CacheEntry is one stored geolocation reply, as shown in the cache viewer.
// Expired marks a reply that is still stored but past its freshness window, so
// the next lookup will refresh it.
type CacheEntry struct {
	IP        string  `json:"ip"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	City      string  `json:"city"`
	Country   string  `json:"country"`
	ASN       string  `json:"asn"`
	FetchedAt int64   `json:"fetchedAt"`
	Expired   bool    `json:"expired"`
}

// CacheInfo describes the persistent geolocation cache for the viewer.
type CacheInfo struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	Count   int    `json:"count"`
}

// geoStore is a persistent SQLite cache of remote geolocation replies. Repeated
// hops — common on nearby stations — are served from here without a lookup.
type geoStore struct {
	db   *sql.DB
	path string
}

// openStore opens (creating if needed) the SQLite cache at path. An empty path
// disables the cache and returns (nil, nil).
func openStore(path string) (*geoStore, error) {
	db, err := sqliteutil.Open(path,
		`CREATE TABLE IF NOT EXISTS geo_cache (
			ip         TEXT PRIMARY KEY,
			lat        REAL NOT NULL,
			lon        REAL NOT NULL,
			city       TEXT NOT NULL,
			country    TEXT NOT NULL,
			asn        TEXT NOT NULL,
			fetched_at INTEGER NOT NULL
		)`,
	)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, nil
	}
	return &geoStore{db: db, path: path}, nil
}

// get returns a fresh cached reply for ip.
func (s *geoStore) get(ctx context.Context, ip string) (GeoData, bool) {
	var (
		data    GeoData
		fetched int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT lat, lon, city, country, asn, fetched_at FROM geo_cache WHERE ip = ?`, ip).
		Scan(&data.Lat, &data.Lon, &data.City, &data.Country, &data.ASN, &fetched)
	if err != nil {
		return GeoData{}, false
	}
	if time.Since(time.Unix(fetched, 0)) > cacheTTL {
		return GeoData{}, false
	}
	data.Resolved = true
	return data, true
}

// put stores a reply for ip, replacing any previous entry.
func (s *geoStore) put(ctx context.Context, ip string, data GeoData) {
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO geo_cache (ip, lat, lon, city, country, asn, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			lat = excluded.lat,
			lon = excluded.lon,
			city = excluded.city,
			country = excluded.country,
			asn = excluded.asn,
			fetched_at = excluded.fetched_at`,
		ip, data.Lat, data.Lon, data.City, data.Country, data.ASN, time.Now().Unix())
}

// Close releases the database handle.
func (s *geoStore) Close() error {
	return s.db.Close()
}

// list returns every stored reply, newest first.
func (s *geoStore) list(ctx context.Context) ([]CacheEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip, lat, lon, city, country, asn, fetched_at
		 FROM geo_cache ORDER BY fetched_at DESC, ip ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now()
	entries := make([]CacheEntry, 0, 64)
	for rows.Next() {
		var entry CacheEntry
		if err := rows.Scan(&entry.IP, &entry.Lat, &entry.Lon, &entry.City,
			&entry.Country, &entry.ASN, &entry.FetchedAt); err != nil {
			return nil, err
		}
		entry.Expired = now.Sub(time.Unix(entry.FetchedAt, 0)) > cacheTTL
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// count returns how many replies are stored.
func (s *geoStore) count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM geo_cache`).Scan(&n)
	return n, err
}

// delete removes one stored reply. Deleting an unknown IP is not an error.
func (s *geoStore) delete(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM geo_cache WHERE ip = ?`, ip)
	return err
}

// clear removes every stored reply.
func (s *geoStore) clear(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM geo_cache`)
	return err
}

// CacheInfo reports the state of the persistent geolocation cache: whether it
// is enabled, where it lives and how many replies it holds.
func (r *Resolver) CacheInfo(ctx context.Context) CacheInfo {
	if r.store == nil {
		return CacheInfo{}
	}
	info := CacheInfo{Enabled: true, Path: r.store.path}
	if n, err := r.store.count(ctx); err == nil {
		info.Count = n
	}
	return info
}

// CacheEntries returns every cached reply, newest first. A disabled cache
// yields an empty slice rather than an error so the viewer stays usable.
func (r *Resolver) CacheEntries(ctx context.Context) ([]CacheEntry, error) {
	if r.store == nil {
		return []CacheEntry{}, nil
	}
	return r.store.list(ctx)
}

// DeleteCacheEntry removes one IP from the persistent cache and drops any
// in-memory copy so the next lookup refreshes it.
func (r *Resolver) DeleteCacheEntry(ctx context.Context, ip string) error {
	r.forget(ip)
	if r.store == nil {
		return nil
	}
	return r.store.delete(ctx, ip)
}

// ClearCache removes every persistent entry and empties the in-memory cache.
func (r *Resolver) ClearCache(ctx context.Context) error {
	r.mu.Lock()
	r.cache = make(map[string]GeoData)
	r.mu.Unlock()
	if r.store == nil {
		return nil
	}
	return r.store.clear(ctx)
}

// forget drops one in-memory entry.
func (r *Resolver) forget(ip string) {
	r.mu.Lock()
	delete(r.cache, ip)
	r.mu.Unlock()
}

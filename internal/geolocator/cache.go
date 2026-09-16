package geolocator

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// cacheTTL is how long a cached reply is considered fresh. Geolocation data is
// fairly stable, so entries live for a month before being refreshed.
const cacheTTL = 30 * 24 * time.Hour

// geoStore is a persistent SQLite cache of remote geolocation replies. Repeated
// hops — common on nearby stations — are served from here without a lookup.
type geoStore struct {
	db   *sql.DB
	path string
}

// openStore opens (creating if needed) the SQLite cache at path. An empty path
// disables the cache and returns (nil, nil).
func openStore(path string) (*geoStore, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection keeps concurrent writers from tripping SQLite's
	// database lock; lookups are rate limited anyway.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS geo_cache (
		ip         TEXT PRIMARY KEY,
		lat        REAL NOT NULL,
		lon        REAL NOT NULL,
		city       TEXT NOT NULL,
		country    TEXT NOT NULL,
		asn        TEXT NOT NULL,
		fetched_at INTEGER NOT NULL
	)`); err != nil {
		_ = db.Close()
		return nil, err
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

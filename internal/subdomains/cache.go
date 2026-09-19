package subdomains

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"traceroute/internal/netutil"
	"traceroute/internal/sqliteutil"
)

// Store is the SQLite-backed subdomain cache, sharing the application database
// (tracemap.db) with the geo cache and history.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the subdomain cache. An empty path disables
// caching and returns (nil, nil).
func Open(path string) (*Store, error) {
	db, err := sqliteutil.Open(path,
		`CREATE TABLE IF NOT EXISTS subdomain (
			domain        TEXT NOT NULL,
			name          TEXT NOT NULL,
			source        TEXT NOT NULL,
			ips           TEXT NOT NULL,
			discovered_at INTEGER NOT NULL,
			PRIMARY KEY (domain, name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_subdomain_domain ON subdomain(domain)`,
	)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, nil
	}
	return &Store{db: db, path: path}, nil
}

// Path returns the database file path, or "" when disabled.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load returns the cached subdomains for domain.
func (s *Store) Load(ctx context.Context, domain string) ([]Result, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, source, ips FROM subdomain WHERE domain = ?`, netutil.NormalizeHost(domain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]Result, 0, 32)
	for rows.Next() {
		var (
			result Result
			ips    string
		)
		if err := rows.Scan(&result.Name, &result.Source, &ips); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ips), &result.IPs)
		results = append(results, result)
	}
	return results, rows.Err()
}

// Save upserts the results for domain.
func (s *Store) Save(ctx context.Context, domain string, results []Result) error {
	if s == nil || len(results) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	for _, result := range results {
		ips, err := json.Marshal(result.IPs)
		if err != nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO subdomain (domain, name, source, ips, discovered_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(domain, name) DO UPDATE SET
				source = excluded.source,
				ips = excluded.ips,
				discovered_at = excluded.discovered_at`,
			netutil.NormalizeHost(domain), result.Name, result.Source, string(ips), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

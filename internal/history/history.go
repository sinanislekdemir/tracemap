// Package history persists completed traces and scans in a local SQLite
// database so they can be revisited and compared on the map.
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"traceroute/internal/sqliteutil"
)

// Geo is the stored geolocation of a hop or target.
type Geo struct {
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	City     string  `json:"city"`
	Country  string  `json:"country"`
	ASN      string  `json:"asn"`
	Resolved bool    `json:"resolved"`
}

// Hop is a single stored hop.
type Hop struct {
	Hop      int     `json:"hop"`
	IP       string  `json:"ip,omitempty"`
	RTTMs    float64 `json:"rttMs,omitempty"`
	Geo      *Geo    `json:"geo,omitempty"`
	IsTarget bool    `json:"isTarget,omitempty"`
}

// Trace is one path within a saved entry. A plain trace holds a single Trace;
// an advanced scan holds one per resolved address.
type Trace struct {
	Label     string `json:"label"`
	Kind      string `json:"kind,omitempty"`
	IP        string `json:"ip,omitempty"`
	TargetIP  string `json:"targetIp,omitempty"`
	TargetGeo *Geo   `json:"targetGeo,omitempty"`
	Hops      []Hop  `json:"hops"`
	Error     string `json:"error,omitempty"`
}

// Entry is a saved trace or scan.
type Entry struct {
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	Label     string  `json:"label"`
	CreatedAt int64   `json:"createdAt"`
	MaxHops   int     `json:"maxHops"`
	Traces    []Trace `json:"traces"`
}

// Summary is the lightweight listing form of an Entry.
type Summary struct {
	ID         int64  `json:"id"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	CreatedAt  int64  `json:"createdAt"`
	TraceCount int    `json:"traceCount"`
	HopCount   int    `json:"hopCount"`
}

// Store is the SQLite-backed history database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the history database at path. An empty path
// disables history and returns (nil, nil).
func Open(path string) (*Store, error) {
	db, err := sqliteutil.Open(path,
		`CREATE TABLE IF NOT EXISTS history_entry (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			kind        TEXT NOT NULL,
			label       TEXT NOT NULL,
			created_at  INTEGER NOT NULL,
			max_hops    INTEGER NOT NULL,
			trace_count INTEGER NOT NULL,
			hop_count   INTEGER NOT NULL,
			data        TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_history_created ON history_entry(created_at DESC)`,
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

// Save stores an entry, stamping CreatedAt when unset, and returns its id.
func (s *Store) Save(ctx context.Context, entry Entry) (int64, error) {
	if s == nil {
		return 0, errors.New("history is disabled")
	}
	if entry.CreatedAt == 0 {
		entry.CreatedAt = time.Now().UnixMilli()
	}
	if entry.Traces == nil {
		entry.Traces = []Trace{}
	}
	data, err := json.Marshal(entry.Traces)
	if err != nil {
		return 0, fmt.Errorf("encode history entry: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO history_entry (kind, label, created_at, max_hops, trace_count, hop_count, data)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entry.Kind, entry.Label, entry.CreatedAt, entry.MaxHops,
		len(entry.Traces), countHops(entry.Traces), string(data))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// List returns every entry summary, newest first.
func (s *Store) List(ctx context.Context) ([]Summary, error) {
	if s == nil {
		return nil, errors.New("history is disabled")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, label, created_at, trace_count, hop_count
		FROM history_entry ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summaries := make([]Summary, 0, 16)
	for rows.Next() {
		var item Summary
		if err := rows.Scan(&item.ID, &item.Kind, &item.Label, &item.CreatedAt,
			&item.TraceCount, &item.HopCount); err != nil {
			return nil, err
		}
		summaries = append(summaries, item)
	}
	return summaries, rows.Err()
}

// Load returns the full entries for ids, oldest first. Unknown ids are skipped.
func (s *Store) Load(ctx context.Context, ids []int64) ([]Entry, error) {
	if s == nil || len(ids) == 0 {
		return []Entry{}, nil
	}

	placeholders := make([]byte, 0, len(ids)*2)
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, id)
	}

	query := fmt.Sprintf(`
		SELECT id, kind, label, created_at, max_hops, data
		FROM history_entry WHERE id IN (%s)
		ORDER BY created_at ASC, id ASC`, string(placeholders))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]Entry, 0, len(ids))
	for rows.Next() {
		var (
			entry Entry
			data  string
		)
		if err := rows.Scan(&entry.ID, &entry.Kind, &entry.Label, &entry.CreatedAt,
			&entry.MaxHops, &data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &entry.Traces); err != nil {
			return nil, fmt.Errorf("decode history entry %d: %w", entry.ID, err)
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// Delete removes a single entry. Deleting an unknown id is not an error.
func (s *Store) Delete(ctx context.Context, id int64) error {
	if s == nil {
		return errors.New("history is disabled")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM history_entry WHERE id = ?`, id)
	return err
}

// Clear removes every entry.
func (s *Store) Clear(ctx context.Context) error {
	if s == nil {
		return errors.New("history is disabled")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM history_entry`)
	return err
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

func countHops(traces []Trace) int {
	total := 0
	for _, trace := range traces {
		total += len(trace.Hops)
	}
	return total
}

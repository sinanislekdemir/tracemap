// Package sqliteutil opens the application's SQLite database with the pragmas
// and single-connection policy shared by the geo, history and subdomain stores.
package sqliteutil

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Open opens (creating if needed) the SQLite database at path, applies the
// shared pragmas, limits the pool to a single connection and runs each schema
// statement. An empty path disables persistence and returns (nil, nil).
func Open(path string, schema ...string) (*sql.DB, error) {
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
	// database lock.
	db.SetMaxOpenConns(1)

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite schema: %w", err)
		}
	}
	return db, nil
}

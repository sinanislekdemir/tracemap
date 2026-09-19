package sqliteutil

import (
	"path/filepath"
	"testing"
)

func TestOpenDisabled(t *testing.T) {
	db, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\"): %v", err)
	}
	if db != nil {
		t.Fatal("expected a nil database for an empty path")
	}
}

func TestOpenCreatesSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "test.db")
	db, err := Open(path, `CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)`)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO t (id) VALUES (1)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
}

func TestOpenInvalidSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	if _, err := Open(path, `NOT VALID SQL`); err == nil {
		t.Fatal("expected an error for an invalid schema statement")
	}
}

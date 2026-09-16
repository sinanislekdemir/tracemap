// Package appdata resolves the location of the application's single SQLite
// database, shared by the geolocation cache and the trace history.
package appdata

import (
	"os"
	"path/filepath"
)

// DefaultName is the application database file name. It holds both the
// geo_cache and history_entry tables.
const DefaultName = "tracemap.db"

// DefaultPath returns the database path: next to the running binary, or the
// user cache directory when that directory is not writable.
// TRACEROUTE_DB overrides it; "off" or "none" disables persistence entirely.
func DefaultPath() string {
	if path := os.Getenv("TRACEROUTE_DB"); path != "" {
		if path == "off" || path == "none" {
			return ""
		}
		return path
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if IsWritable(dir) {
			return filepath.Join(dir, DefaultName)
		}
	}
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "traceroute", DefaultName)
	}
	return ""
}

// IsWritable reports whether dir accepts new files, by creating and removing a
// temporary file. This catches read-only mounts and permission denials that a
// simple mode check would miss.
func IsWritable(dir string) bool {
	file, err := os.CreateTemp(dir, ".tracemap-probe-*")
	if err != nil {
		return false
	}
	name := file.Name()
	_ = file.Close()
	_ = os.Remove(name)
	return true
}

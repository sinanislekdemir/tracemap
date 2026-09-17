// Package appdata resolves the location of the application's single SQLite
// database, shared by the geolocation cache, trace history and subdomain cache.
package appdata

import (
	"os"
	"path/filepath"
)

// DefaultName is the application database file name. It holds the geo_cache,
// history_entry and subdomain tables.
const DefaultName = "tracemap.db"

// dirName is the per-user directory the database lives in.
const dirName = "traceroute"

// DefaultPath returns the database path under the user's configuration
// directory (e.g. ~/.config/traceroute/tracemap.db on Linux,
// ~/Library/Application Support/traceroute/tracemap.db on macOS,
// %AppData%\traceroute\tracemap.db on Windows), so the location is stable and
// independent of where the binary runs.
//
// TRACEROUTE_DB overrides it; "off" or "none" disables persistence entirely.
func DefaultPath() string {
	if path := os.Getenv("TRACEROUTE_DB"); path != "" {
		if path == "off" || path == "none" {
			return ""
		}
		return path
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, dirName, DefaultName)
	}
	// Fall back to a dot-directory in the home folder.
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "."+dirName, DefaultName)
	}
	return ""
}

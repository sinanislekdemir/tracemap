// Package appdata resolves the location of the application's single SQLite
// database, shared by the geolocation cache, trace history and subdomain cache.
package appdata

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultName is the application database file name. It holds the geo_cache,
// history_entry and subdomain tables.
const DefaultName = "tracemap.db"

// ScrapeDBName is the file name of the separate scrape/archive database. It is
// kept apart from DefaultName so a large archive can be deleted or backed up on
// its own.
const ScrapeDBName = "scrape.db"

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

// DataDir returns the per-user data directory that holds the scrape archive
// (the scrape database and downloaded media). It is separate from the config
// directory because archives grow far larger than configuration:
//
//   - Linux:   $XDG_DATA_HOME/traceroute (default ~/.local/share/traceroute)
//   - macOS:   ~/Library/Application Support/traceroute
//   - Windows: %LocalAppData%\traceroute
//
// TRACEROUTE_DATA overrides it; "off" or "none" disables scraping. It returns
// "" when no directory can be determined.
func DataDir() string {
	if path := os.Getenv("TRACEROUTE_DATA"); path != "" {
		if path == "off" || path == "none" {
			return ""
		}
		return path
	}
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("LocalAppData"); dir != "" {
			return filepath.Join(dir, dirName)
		}
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, dirName)
		}
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", dirName)
		}
	default:
		if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
			return filepath.Join(dir, dirName)
		}
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".local", "share", dirName)
		}
	}
	return ""
}

// ConfigDir returns the per-user configuration directory that holds the
// database and any user-maintained rule files. It is derived from DefaultPath
// so the two always agree. It returns "" when no configuration directory can
// be determined (or when persistence is disabled via TRACEROUTE_DB).
func ConfigDir() string {
	if path := DefaultPath(); path != "" {
		return filepath.Dir(path)
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, dirName)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "."+dirName)
	}
	return ""
}

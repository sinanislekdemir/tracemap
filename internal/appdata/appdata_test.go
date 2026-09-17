package appdata

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPathEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.db")
	t.Setenv("TRACEROUTE_DB", path)
	if got := DefaultPath(); got != path {
		t.Errorf("DefaultPath = %q, want %q", got, path)
	}

	t.Setenv("TRACEROUTE_DB", "off")
	if got := DefaultPath(); got != "" {
		t.Errorf("DefaultPath = %q, want empty when disabled", got)
	}
}

func TestDefaultPathName(t *testing.T) {
	if DefaultName != "tracemap.db" {
		t.Errorf("DefaultName = %q, want tracemap.db", DefaultName)
	}
}

func TestDefaultPathIsUnderHomeConfig(t *testing.T) {
	t.Setenv("TRACEROUTE_DB", "")
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no user config dir: %v", err)
	}
	want := filepath.Join(dir, "traceroute", "tracemap.db")
	if got := DefaultPath(); got != want {
		t.Errorf("DefaultPath = %q, want %q", got, want)
	}
}

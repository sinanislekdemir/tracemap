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

func TestIsWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}
	if !IsWritable(t.TempDir()) {
		t.Error("expected a temp dir to be writable")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if IsWritable(dir) {
		t.Error("expected a read-only dir to be unwritable")
	}
}

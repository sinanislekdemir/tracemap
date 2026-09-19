package subdomains

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWordlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	content := "# comment\nwww\napi.example.com\n\nWWW\nMail\n  dev  \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	words, err := LoadWordlist(path)
	if err != nil {
		t.Fatalf("LoadWordlist: %v", err)
	}
	want := []string{"www", "api", "mail", "dev"}
	if len(words) != len(want) {
		t.Fatalf("words = %v, want %v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Errorf("words[%d] = %q, want %q", i, words[i], want[i])
		}
	}
}

func TestLoadWordlistMissingFile(t *testing.T) {
	if _, err := LoadWordlist(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

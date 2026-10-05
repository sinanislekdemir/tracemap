package cheatsheets

import "testing"

func TestAll(t *testing.T) {
	all := All()
	if len(all) < 8 {
		t.Fatalf("sheets = %d, want >= 8", len(all))
	}
	for _, s := range all {
		if s.ID == "" || s.Protocol == "" || len(s.Groups) == 0 {
			t.Fatalf("incomplete sheet: %q", s.ID)
		}
		for _, g := range s.Groups {
			if g.Name == "" || len(g.Commands) == 0 {
				t.Fatalf("incomplete group in %q", s.ID)
			}
		}
	}
	if Find("ftp") == nil {
		t.Fatal("Find(ftp) = nil")
	}
	if Find("nope") != nil {
		t.Fatal("Find(nope) != nil")
	}
}

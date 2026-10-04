package ipblocks

import (
	"context"
	"net/netip"
	"testing"
)

func TestPaginateFiltersAndPages(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	all := Paginate(prefixes, Query{})
	if all.Total != 3 || all.Matched != 3 {
		t.Fatalf("all: total=%d matched=%d, want 3/3", all.Total, all.Matched)
	}
	if len(all.Blocks) != 3 || all.Truncated {
		t.Fatalf("all: blocks=%d truncated=%v", len(all.Blocks), all.Truncated)
	}

	v4 := Paginate(prefixes, Query{Family: "ipv4"})
	if v4.Matched != 2 {
		t.Errorf("ipv4 matched=%d, want 2", v4.Matched)
	}
	v6 := Paginate(prefixes, Query{Family: "ipv6"})
	if v6.Matched != 1 || v6.Blocks[0] != "2001:db8::/32" {
		t.Errorf("ipv6 = %+v, want the db8 prefix", v6)
	}

	filtered := Paginate(prefixes, Query{Filter: "192.168"})
	if filtered.Matched != 1 || filtered.Blocks[0] != "192.168.0.0/16" {
		t.Errorf("filter = %+v, want the 192.168 prefix", filtered)
	}

	limited := Paginate(prefixes, Query{Limit: 1})
	if limited.Matched != 3 || len(limited.Blocks) != 1 || !limited.Truncated {
		t.Errorf("limit = %+v, want 3 matched / 1 shown / truncated", limited)
	}

	full := Paginate(prefixes, Query{Limit: -1})
	if full.Matched != 3 || len(full.Blocks) != 3 || full.Truncated {
		t.Errorf("negative limit = %+v, want every block", full)
	}
}

func TestPaginateAddressCount(t *testing.T) {
	page := Paginate([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Query{})
	if page.Addresses != "16.78M" {
		t.Errorf("Addresses = %q, want 16.78M", page.Addresses)
	}
}

func TestHumanCount(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{42, "42"},
		{1500, "1.50K"},
		{2_500_000, "2.50M"},
		{3_000_000_000, "3.00B"},
	}
	for _, tt := range tests {
		if got := humanCount(tt.in); got != tt.want {
			t.Errorf("humanCount(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestRealDatabase exercises the installed GeoLite2 database when one is
// present; it is skipped otherwise so the suite stays offline-friendly.
func TestRealDatabase(t *testing.T) {
	db, err := Open()
	if err != nil {
		t.Skipf("no local GeoLite2 database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	countries, err := db.Countries(ctx, nil)
	if err != nil {
		t.Fatalf("Countries: %v", err)
	}
	if len(countries) == 0 {
		t.Fatal("no countries found")
	}
	top := countries[0]
	if top.Code == "" || top.Blocks == 0 {
		t.Fatalf("top country = %+v, want a code and blocks", top)
	}

	page, err := db.Query(ctx, top.Code, Query{Limit: 10}, nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if page.Total != top.Blocks {
		t.Errorf("page.Total = %d, want %d (summary blocks)", page.Total, top.Blocks)
	}
	if page.Matched == 0 || len(page.Blocks) == 0 {
		t.Fatalf("page = %+v, want blocks", page)
	}
	if page.Matched > 10 && !page.Truncated {
		t.Errorf("page not marked truncated: %+v", page)
	}
}

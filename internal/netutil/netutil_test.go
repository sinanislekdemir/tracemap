package netutil

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM.": "example.com",
		"  host  ":     "host",
		"a.b.c":        "a.b.c",
		"":             "",
	}
	for input, want := range cases {
		if got := NormalizeHost(input); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/path?q=1": "example.com",
		"http://example.com:8080/x":    "example.com",
		"example.com.":                 "example.com",
		"  example.com  ":              "example.com",
		"example.com:8443":             "example.com",
		"[::1]:443":                    "::1",
		"::1":                          "::1",
		"":                             "",
	}
	for input, want := range cases {
		if got := NormalizeDomain(input); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	public := []string{"8.8.8.8", "2001:4860:4860::8888"}
	private := []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1", "not-an-ip", ""}
	for _, ip := range public {
		if !IsPublicIP(ip) {
			t.Errorf("IsPublicIP(%q) = false, want true", ip)
		}
	}
	for _, ip := range private {
		if IsPublicIP(ip) {
			t.Errorf("IsPublicIP(%q) = true, want false", ip)
		}
	}
}

func TestIsStrictSubdomain(t *testing.T) {
	cases := []struct {
		name, domain string
		want         bool
	}{
		{"a.example.com", "example.com", true},
		{"example.com", "example.com", false},
		{"badexample.com", "example.com", false},
		{"a.example.com", "", false},
		{"", "example.com", false},
	}
	for _, tc := range cases {
		if got := IsStrictSubdomain(tc.name, tc.domain); got != tc.want {
			t.Errorf("IsStrictSubdomain(%q, %q) = %t, want %t", tc.name, tc.domain, got, tc.want)
		}
	}
}

func TestIsSameSite(t *testing.T) {
	if !IsSameSite("example.com", "example.com") {
		t.Error("apex should be same site")
	}
	if !IsSameSite("www.example.com", "example.com") {
		t.Error("subdomain should be same site")
	}
	if IsSameSite("example.org", "example.com") {
		t.Error("unrelated domain should not be same site")
	}
}

func TestDedupe(t *testing.T) {
	got := Dedupe([]string{"a", "", " a ", "b", "b"})
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Dedupe = %v, want %v", got, want)
	}
}

func TestMergeUnique(t *testing.T) {
	base := []string{"a", "b"}
	got := MergeUnique(base, []string{"b", "c", ""})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeUnique = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(base, []string{"a", "b"}) {
		t.Errorf("MergeUnique mutated base: %v", base)
	}
}

func TestSortedKeys(t *testing.T) {
	got := SortedKeys(map[string]int{"b": 1, "a": 2})
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SortedKeys = %v, want %v", got, want)
	}
}

func TestCap(t *testing.T) {
	values := []int{1, 2, 3}
	if got := Cap(values, 2); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf("Cap(2) = %v", got)
	}
	if got := Cap(values, 0); !reflect.DeepEqual(got, values) {
		t.Errorf("Cap(0) = %v, want unchanged", got)
	}
	if got := Cap(values, 10); !reflect.DeepEqual(got, values) {
		t.Errorf("Cap(10) = %v, want unchanged", got)
	}
}

type fakeResolver struct {
	ips []net.IP
	err error
}

func (f fakeResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return f.ips, f.err
}

func TestResolveIPs(t *testing.T) {
	resolver := fakeResolver{ips: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("::1")}}
	got := ResolveIPs(context.Background(), resolver, "example.com")
	want := []string{"1.2.3.4", "::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveIPs = %v, want %v", got, want)
	}

	failing := fakeResolver{err: errors.New("boom")}
	if got := ResolveIPs(context.Background(), failing, "example.com"); got != nil {
		t.Errorf("ResolveIPs on error = %v, want nil", got)
	}
}

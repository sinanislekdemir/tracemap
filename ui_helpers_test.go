package main

import "testing"

func TestParseBlockTarget(t *testing.T) {
	cases := []struct {
		in    string
		cidr  string
		ports string
		ok    bool
	}{
		{"2.59.40.0/22:21", "2.59.40.0/22", "21", true},
		{"10.0.0.0/24:22,80,443-445", "10.0.0.0/24", "22,80,443-445", true},
		{"10.0.0.0/24", "10.0.0.0/24", "", true},
		{"192.168.1.7/24", "192.168.1.7/24", "", true},
		{"example.com", "", "", false},
		{"1.1.1.1", "", "", false},
		{"10.0.0.0/24:99999", "", "", false},
		{"10.0.0.0/33", "", "", false},
	}
	for _, c := range cases {
		cidr, ports, ok := parseBlockTarget(c.in)
		if ok != c.ok || cidr != c.cidr || ports != c.ports {
			t.Errorf("parseBlockTarget(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, cidr, ports, ok, c.cidr, c.ports, c.ok)
		}
	}
}

func TestFormatCount(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0"},
		{2, "2"},
		{254, "254"},
		{1000, "1,000"},
		{65534, "65,534"},
		{16777214, "16,777,214"},
	}
	for _, c := range cases {
		if got := formatCount(c.in); got != c.want {
			t.Errorf("formatCount(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBlockHostCount(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.0.0/24", "254", true},
		{"10.0.0.0/22", "1,022", true},
		{"192.168.1.7/24", "254", true},
		{"10.0.0.0/32", "1", true},
		{"10.0.0.0/31", "2", true},
		{"example.com", "", false},
	}
	for _, c := range cases {
		got, ok := blockHostCount(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("blockHostCount(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

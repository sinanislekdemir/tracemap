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

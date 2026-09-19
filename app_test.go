package main

import (
	"strings"
	"testing"
)

func TestNormalizePortScanTargets(t *testing.T) {
	tests := []struct {
		name string
		req  PortScanRequest
		want []PortScanTarget
	}{
		{
			name: "falls back to host",
			req:  PortScanRequest{Host: "  example.com "},
			want: []PortScanTarget{{Label: "example.com", Host: "example.com"}},
		},
		{
			name: "trims, dedupes and fills labels",
			req: PortScanRequest{Targets: []PortScanTarget{
				{Label: "web", Host: " 10.0.0.1 "},
				{Label: "", Host: "10.0.0.1"},
				{Label: "db", Host: "10.0.0.2"},
				{Host: "   "},
			}},
			want: []PortScanTarget{
				{Label: "web", Host: "10.0.0.1"},
				{Label: "db", Host: "10.0.0.2"},
			},
		},
		{
			name: "empty request yields nothing",
			req:  PortScanRequest{},
			want: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizePortScanTargets(test.req)
			if len(got) != len(test.want) {
				t.Fatalf("got %d targets, want %d: %#v", len(got), len(test.want), got)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Errorf("target %d = %#v, want %#v", i, got[i], test.want[i])
				}
			}
		})
	}
}

func TestFormatPortScanTSV(t *testing.T) {
	rows := []PortScanRow{
		{
			Host: "10.0.0.1", Label: "web", Port: 443, Protocol: "tcp",
			Service: "https", Product: "nginx", TLS: true, Detail: "TLS 1.3",
		},
		{
			Host: "10.0.0.2", Label: "db", Port: 3306, Protocol: "tcp",
			Service: "mysql", Banner: "8.0.36\tready\nline", Detail: "",
		},
	}

	out := formatPortScanTSV(rows)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), out)
	}
	if lines[0] != strings.Join(portScanTSVHeader, "\t") {
		t.Errorf("header = %q", lines[0])
	}
	if want := "10.0.0.1\tweb\t443\ttcp\thttps\tnginx\tyes\tTLS 1.3"; lines[1] != want {
		t.Errorf("row 1 = %q, want %q", lines[1], want)
	}
	// Tabs/newlines in a field are collapsed and banner is used when detail is empty.
	if want := "10.0.0.2\tdb\t3306\ttcp\tmysql\t\t\t8.0.36 ready line"; lines[2] != want {
		t.Errorf("row 2 = %q, want %q", lines[2], want)
	}
}

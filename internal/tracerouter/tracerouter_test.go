package tracerouter

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []Hop
	}{
		{
			name: "unix output",
			input: "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n" +
				" 1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms\n" +
				" 2  10.0.0.1  5.000 ms  *  5.100 ms\n" +
				" 3  93.184.216.34  12.340 ms  12.500 ms  12.600 ms\n",
			expected: []Hop{
				{Number: 1, IP: "192.168.1.1", RTTs: []time.Duration{1234 * time.Microsecond, 1100 * time.Microsecond, 1050 * time.Microsecond}},
				{Number: 2, IP: "10.0.0.1", RTTs: []time.Duration{5 * time.Millisecond, 5100 * time.Microsecond}},
				{Number: 3, IP: "93.184.216.34", RTTs: []time.Duration{12340 * time.Microsecond, 12500 * time.Microsecond, 12600 * time.Microsecond}},
			},
		},
		{
			name: "windows output",
			input: "Tracing route to example.com [93.184.216.34]\nover a maximum of 30 hops:\n\n" +
				"  1     1 ms     1 ms     1 ms  192.168.1.1\n" +
				"  2    10 ms    11 ms    10 ms  10.0.0.1\n" +
				"  3     *        *        *     Request timed out.\n",
			expected: []Hop{
				{Number: 1, IP: "192.168.1.1", RTTs: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}},
				{Number: 2, IP: "10.0.0.1", RTTs: []time.Duration{10 * time.Millisecond, 11 * time.Millisecond, 10 * time.Millisecond}},
				{Number: 3},
			},
		},
		{
			name:     "unresponsive hop",
			input:    " 5  * * *\n 6  8.8.8.8  20.0 ms\n",
			expected: []Hop{{Number: 5}, {Number: 6, IP: "8.8.8.8", RTTs: []time.Duration{20 * time.Millisecond}}},
		},
		{
			name:     "non-hop lines ignored",
			input:    "traceroute to x\nsome note 1 ms\n",
			expected: nil,
		},
		{
			name: "tracepath output merges repeated probes",
			input: " 1?: [LOCALHOST]                      pmtu 1500\n" +
				" 1:  192.168.1.1                       0.282ms \n" +
				" 1:  192.168.1.1                       0.270ms \n" +
				" 2:  10.0.0.1                          1.234ms asymm 3\n" +
				" 3:  no reply\n",
			expected: []Hop{
				{Number: 1, IP: "192.168.1.1", RTTs: []time.Duration{282 * time.Microsecond, 270 * time.Microsecond}},
				{Number: 2, IP: "10.0.0.1", RTTs: []time.Duration{1234 * time.Microsecond}},
				{Number: 3},
			},
		},
		{
			name: "tracepath keeps a later address for the same hop",
			input: " 1?: [LOCALHOST]                      pmtu 1500\n" +
				" 1:  192.168.1.1                       0.282ms \n",
			expected: []Hop{
				{Number: 1, IP: "192.168.1.1", RTTs: []time.Duration{282 * time.Microsecond}},
			},
		},
		{
			name: "mtr report output",
			input: "Start: 2026-09-16T00:00:00+0000\n" +
				"HOST: host                          Loss%   Snt   Last   Avg  Best  Wrst StDev\n" +
				"  1.|-- 192.168.1.1                  0.0%     1    0.3   0.3   0.3   0.3   0.0\n" +
				"  2.|-- 10.0.0.1                     0.0%     1    5.0   5.0   5.0   5.0   0.0\n" +
				"  3.|-- ???                        100.0     1    0.0   0.0   0.0   0.0   0.0\n",
			expected: []Hop{
				{Number: 1, IP: "192.168.1.1", RTTs: []time.Duration{300 * time.Microsecond}},
				{Number: 2, IP: "10.0.0.1", RTTs: []time.Duration{5 * time.Millisecond}},
				{Number: 3},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("got %d hops, want %d: %+v", len(got), len(tt.expected), got)
			}
			for i := range got {
				if got[i].Number != tt.expected[i].Number || got[i].IP != tt.expected[i].IP {
					t.Errorf("hop %d = %+v, want %+v", i, got[i], tt.expected[i])
					continue
				}
				if len(got[i].RTTs) != len(tt.expected[i].RTTs) {
					t.Errorf("hop %d RTTs = %v, want %v", i, got[i].RTTs, tt.expected[i].RTTs)
					continue
				}
				for j := range got[i].RTTs {
					if got[i].RTTs[j] != tt.expected[i].RTTs[j] {
						t.Errorf("hop %d RTT %d = %v, want %v", i, j, got[i].RTTs[j], tt.expected[i].RTTs[j])
					}
				}
			}
		})
	}
}

func TestToolFromBinary(t *testing.T) {
	tests := map[string]tool{
		"traceroute":                      toolTraceroute,
		"/usr/bin/traceroute":             toolTraceroute,
		"fake-traceroute":                 toolTraceroute,
		"tracert":                         toolTracert,
		"tracert.exe":                     toolTracert,
		`C:\Windows\System32\tracert.exe`: toolTracert,
		"/usr/bin/tracepath":              toolTracepath,
		"mtr":                             toolMtr,
		"/usr/local/sbin/mtr":             toolMtr,
	}
	for path, want := range tests {
		if got := toolFromBinary(path); got != want {
			t.Errorf("toolFromBinary(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestArgsFor(t *testing.T) {
	const (
		maxHops = 30
		timeout = 30 * time.Second
	)
	tests := []struct {
		name    string
		tool    tool
		resolve bool
		want    []string
	}{
		{"traceroute", toolTraceroute, false, []string{"-n", "-m", "30", "-w", "10", "-q", "3"}},
		{"traceroute names", toolTraceroute, true, []string{"-m", "30", "-w", "10", "-q", "3"}},
		{"tracert", toolTracert, false, []string{"-d", "-h", "30", "-w", "10000"}},
		{"tracert names", toolTracert, true, []string{"-h", "30", "-w", "10000"}},
		{"tracepath", toolTracepath, false, []string{"-n", "-m", "30"}},
		{"tracepath names", toolTracepath, true, []string{"-m", "30"}},
		{"mtr", toolMtr, false, []string{"-n", "-r", "-c", "1", "-m", "30"}},
		{"mtr names", toolMtr, true, []string{"-r", "-c", "1", "-m", "30"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := argsFor(tt.tool, maxHops, tt.resolve, timeout)
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("argsFor = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCandidatesFor(t *testing.T) {
	windows := candidatesFor("windows")
	if len(windows) == 0 || windows[0].name != "tracert" {
		t.Errorf("windows candidates = %+v, want tracert first", windows)
	}

	unix := candidatesFor("linux")
	if len(unix) != 3 {
		t.Fatalf("linux candidates = %+v, want 3", unix)
	}
	if unix[0].name != "traceroute" || unix[1].name != "tracepath" || unix[2].name != "mtr" {
		t.Errorf("linux candidate order = %q, %q, %q", unix[0].name, unix[1].name, unix[2].name)
	}
}

func TestValidateTarget(t *testing.T) {
	valid := []string{"example.com", "8.8.8.8", "2001:4860:4860::8888", "sub.domain.example.org", "host-name"}
	for _, target := range valid {
		if err := validateTarget(target); err != nil {
			t.Errorf("validateTarget(%q) = %v, want nil", target, err)
		}
	}

	invalid := []string{"", "-flag", "example.com; rm -rf /", "foo bar", "$(whoami)", "a/../b", "host\nname"}
	for _, target := range invalid {
		if err := validateTarget(target); err == nil {
			t.Errorf("validateTarget(%q) = nil, want error", target)
		}
	}
}

func TestExecuteStreamWithFakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake binary is not portable to Windows")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "fake-traceroute")
	content := "#!/bin/sh\n" +
		"cat <<'EOF'\n" +
		"traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n" +
		" 1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms\n" +
		" 2  * * *\n" +
		" 3  93.184.216.34  12.340 ms  12.500 ms  12.600 ms\n" +
		"EOF\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	runner := &Runner{Binary: script}
	hops, err := runner.Execute(context.Background(), "example.com", Options{MaxHops: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(hops) != 3 {
		t.Fatalf("got %d hops, want 3: %+v", len(hops), hops)
	}
	if hops[1].Responded() {
		t.Errorf("hop 2 should be unresponsive: %+v", hops[1])
	}
	if hops[2].BestRTT() != 12340*time.Microsecond {
		t.Errorf("hop 3 best RTT = %v, want 12.34ms", hops[2].BestRTT())
	}
}

func TestExecuteRejectsInvalidTarget(t *testing.T) {
	runner := NewRunner()
	if _, err := runner.Execute(context.Background(), "example.com; rm -rf /", Options{}); err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestExecuteSurfacesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake binary is not portable to Windows")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "fake-traceroute")
	content := "#!/bin/sh\n" +
		"echo 'no-such-host.invalid: Name or service not known' >&2\n" +
		"exit 2\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	runner := &Runner{Binary: script}
	err := runner.ExecuteStream(context.Background(), "no-such-host.invalid", Options{MaxHops: 10, Timeout: 5 * time.Second}, Observer{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Name or service not known") {
		t.Errorf("error %q should include stderr", err)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		line string
		want string
		ok   bool
	}{
		{"traceroute to example.com (104.20.23.154), 30 hops max, 60 byte packets", "104.20.23.154", true},
		{"traceroute to 1.1.1.1 (1.1.1.1), 64 hops max, 52 byte packets", "1.1.1.1", true},
		{"traceroute to example.com (2606:2800:220:1:248:1893:25c8:1946), 30 hops max", "2606:2800:220:1:248:1893:25c8:1946", true},
		{"Tracing route to example.com [93.184.216.34]", "93.184.216.34", true},
		{" 1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms", "", false},
		{"traceroute to example.com, 30 hops max", "", false},
	}

	for _, tt := range tests {
		got, ok := ParseTarget(tt.line)
		if ok != tt.ok || got != tt.want {
			t.Errorf("ParseTarget(%q) = (%q, %v), want (%q, %v)", tt.line, got, ok, tt.want, tt.ok)
		}
	}
}

func TestExecuteStreamReportsTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake binary is not portable to Windows")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "fake-traceroute")
	content := "#!/bin/sh\n" +
		"echo 'traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets'\n" +
		"echo ' 1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms'\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	runner := &Runner{Binary: script}
	var targetIP string
	hops := 0
	err := runner.ExecuteStream(context.Background(), "example.com", Options{MaxHops: 10, Timeout: 5 * time.Second}, Observer{
		OnHop:    func(Hop) { hops++ },
		OnTarget: func(ip string) { targetIP = ip },
	})
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	if targetIP != "93.184.216.34" {
		t.Errorf("target IP = %q, want 93.184.216.34", targetIP)
	}
	if hops != 1 {
		t.Errorf("got %d hops, want 1", hops)
	}
}

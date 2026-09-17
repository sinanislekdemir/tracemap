package portscan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{name: "single", spec: "80", want: []int{80}},
		{name: "list", spec: "22,80,443", want: []int{22, 80, 443}},
		{name: "range", spec: "20-23", want: []int{20, 21, 22, 23}},
		{name: "mixed", spec: "22,80-82", want: []int{22, 80, 81, 82}},
		{name: "dedupe", spec: "80,80,79-80", want: []int{79, 80}},
		{name: "spaces", spec: " 22 , 80 ", want: []int{22, 80}},
		{name: "empty", spec: "", wantErr: true},
		{name: "not a number", spec: "abc", wantErr: true},
		{name: "reversed range", spec: "100-50", wantErr: true},
		{name: "zero", spec: "0", wantErr: true},
		{name: "too high", spec: "70000", wantErr: true},
		{name: "only commas", spec: ",,,", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePorts(%q) = %v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePorts(%q) unexpected error: %v", tt.spec, err)
			}
			if !equalInts(got, tt.want) {
				t.Fatalf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestPresets(t *testing.T) {
	if len(Top20) != 20 {
		t.Errorf("Top20 has %d ports, want 20", len(Top20))
	}
	if len(Top100) != 100 {
		t.Errorf("Top100 has %d ports, want 100", len(Top100))
	}
	if len(Top1000) < 1024 {
		t.Errorf("Top1000 has %d ports, want at least 1024", len(Top1000))
	}

	defaults, err := PresetPorts("")
	if err != nil {
		t.Fatalf("PresetPorts(\"\") error: %v", err)
	}
	if !equalInts(defaults, Top100) {
		t.Errorf("empty preset should default to Top100")
	}

	if _, err := PresetPorts("nope"); err == nil {
		t.Errorf("PresetPorts(\"nope\") should fail")
	}

	// Presets must not alias their source, so a caller cannot corrupt them.
	ports, err := PresetPorts("top20")
	if err != nil {
		t.Fatalf("PresetPorts(top20) error: %v", err)
	}
	ports[0] = 99999
	again, _ := PresetPorts("top20")
	if again[0] == 99999 {
		t.Errorf("PresetPorts returned a shared slice")
	}
}

func TestServiceName(t *testing.T) {
	if got := ServiceName(22); got != "ssh" {
		t.Errorf("ServiceName(22) = %q, want ssh", got)
	}
	if got := ServiceName(65000); got != "" {
		t.Errorf("ServiceName(65000) = %q, want empty", got)
	}
}

func TestScanFindsOpenTCPPort(t *testing.T) {
	port, closeLn := listenTCP(t)
	defer closeLn()

	results, err := NewScanner().Scan(context.Background(), "127.0.0.1", Options{
		Ports:       []int{port},
		Concurrency: 2,
		Timeout:     300 * time.Millisecond,
	}, Observer{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 1 || results[0].Port != port {
		t.Fatalf("Scan = %v, want port %d open", results, port)
	}
	if results[0].Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", results[0].Protocol)
	}
}

func TestScanIgnoresClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	results, err := NewScanner().Scan(context.Background(), "127.0.0.1", Options{
		Ports:   []int{port},
		Timeout: 150 * time.Millisecond,
	}, Observer{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("Scan = %v, want no open ports", results)
	}
}

func TestScanContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ports := make([]int, 500)
	for i := range ports {
		ports[i] = 10000 + i
	}
	_, err := NewScanner().Scan(ctx, "127.0.0.1", Options{Ports: ports}, Observer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan error = %v, want context.Canceled", err)
	}
}

func TestScanUsesDialContext(t *testing.T) {
	called := false
	scanner := &Scanner{DialContext: func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("refused")
	}}

	if _, err := scanner.Scan(context.Background(), "127.0.0.1", Options{Ports: []int{80}}, Observer{}); err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !called {
		t.Fatalf("DialContext override was not used")
	}
}

func TestObserverCallbacks(t *testing.T) {
	port, closeLn := listenTCP(t)
	defer closeLn()

	var opens, lastDone, lastTotal, lastOpen int
	_, err := NewScanner().Scan(context.Background(), "127.0.0.1", Options{
		Ports:   []int{port},
		Timeout: 300 * time.Millisecond,
	}, Observer{
		OnOpen:     func(Result) { opens++ },
		OnProgress: func(done, total, open int) { lastDone, lastTotal, lastOpen = done, total, open },
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if opens != 1 {
		t.Errorf("OnOpen calls = %d, want 1", opens)
	}
	if lastDone != 1 || lastTotal != 1 || lastOpen != 1 {
		t.Errorf("last progress = (%d,%d,%d), want (1,1,1)", lastDone, lastTotal, lastOpen)
	}
}

func TestProbeHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "tracemap-test/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	results, err := NewScanner().Scan(context.Background(), "127.0.0.1", Options{
		Ports:   []int{portOf(t, server.URL)},
		Timeout: 500 * time.Millisecond,
		Probe:   true,
	}, Observer{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Scan = %v, want one open port", results)
	}
	if results[0].Product != "tracemap-test/1.0" {
		t.Errorf("Product = %q, want tracemap-test/1.0", results[0].Product)
	}
	if !strings.HasPrefix(results[0].Banner, "HTTP/") {
		t.Errorf("Banner = %q, want an HTTP status line", results[0].Banner)
	}
	if results[0].TLS {
		t.Errorf("TLS = true for a plain HTTP server")
	}
}

func TestProbeTLSOnUnknownPort(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	results, err := NewScanner().Scan(context.Background(), "127.0.0.1", Options{
		Ports:   []int{portOf(t, server.URL)},
		Timeout: 700 * time.Millisecond,
		Probe:   true,
	}, Observer{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Scan = %v, want one open port", results)
	}
	if !results[0].TLS {
		t.Fatalf("TLS = false, want TLS detected on an unknown port")
	}
	if results[0].Product == "" {
		t.Errorf("Product (cert CN) is empty")
	}
}

func TestScanUDPEcho(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	results, err := NewScanner().Scan(context.Background(), "127.0.0.1", Options{
		Protocol: "udp",
		Ports:    []int{port},
		Timeout:  400 * time.Millisecond,
	}, Observer{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 1 || results[0].Protocol != "udp" {
		t.Fatalf("Scan = %v, want UDP port %d open", results, port)
	}
}

func listenTCP(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

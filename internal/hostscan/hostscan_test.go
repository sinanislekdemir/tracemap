package hostscan

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNet string
		wantOK  bool
	}{
		{"plain block", "10.0.0.0/24", "10.0.0.0/24", true},
		{"host bits set", "192.168.1.7/24", "192.168.1.0/24", true},
		{"single host", "192.168.1.5/32", "192.168.1.5/32", true},
		{"space padded", "  172.16.0.0/16  ", "172.16.0.0/16", true},
		{"bare ip", "10.0.0.1", "", false},
		{"hostname", "example.com", "", false},
		{"ipv6", "2001:db8::/32", "", false},
		{"garbage", "10.0.0.0/33", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, ok := ParseCIDR(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("ParseCIDR(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			ones, bits := network.Mask.Size()
			got := network.IP.String() + "/" + strconv.Itoa(ones)
			if bits != 32 {
				t.Fatalf("mask is not IPv4: %d/%d", ones, bits)
			}
			if got != tt.wantNet {
				t.Fatalf("ParseCIDR(%q) = %s, want %s", tt.input, got, tt.wantNet)
			}
		})
	}
}

func TestCount(t *testing.T) {
	tests := []struct {
		cidr string
		want uint64
	}{
		{"10.0.0.0/24", 254},
		{"10.0.0.0/30", 2},
		{"10.0.0.0/31", 2},
		{"10.0.0.1/32", 1},
		{"10.0.0.0/29", 6},
	}
	for _, tt := range tests {
		network, ok := ParseCIDR(tt.cidr)
		if !ok {
			t.Fatalf("ParseCIDR(%q) failed", tt.cidr)
		}
		if got := Count(network); got != tt.want {
			t.Fatalf("Count(%s) = %d, want %d", tt.cidr, got, tt.want)
		}
	}
}

func TestEach(t *testing.T) {
	network, ok := ParseCIDR("192.168.1.0/30")
	if !ok {
		t.Fatalf("ParseCIDR failed")
	}
	var got []string
	Each(network, func(ip string) bool {
		got = append(got, ip)
		return true
	})
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Each = %v, want %v", got, want)
	}
}

func TestEachStopsEarly(t *testing.T) {
	network, _ := ParseCIDR("192.168.1.0/24")
	seen := 0
	Each(network, func(ip string) bool {
		seen++
		return seen < 3
	})
	if seen != 3 {
		t.Fatalf("visited %d hosts, want 3", seen)
	}
}

func TestEachSlash31(t *testing.T) {
	network, _ := ParseCIDR("192.168.1.0/31")
	var got []string
	Each(network, func(ip string) bool {
		got = append(got, ip)
		return true
	})
	want := []string{"192.168.1.0", "192.168.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Each(/31) = %v, want %v", got, want)
	}
}

func TestDiscoverFindsLiveHosts(t *testing.T) {
	network, ok := ParseCIDR("192.168.1.0/29")
	if !ok {
		t.Fatalf("ParseCIDR failed")
	}

	scanner := &Scanner{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if host == "192.168.1.3" && port == "80" {
				client, server := net.Pipe()
				go func() { _ = server.Close() }()
				return client, nil
			}
			return nil, errors.New("connection refused")
		},
	}

	var (
		found    []string
		progress int
	)
	live, err := scanner.Discover(context.Background(), network, Options{
		Ports:       []int{80, 443},
		Concurrency: 2,
	}, Observer{
		OnFound:    func(host string, _ int) { found = append(found, host) },
		OnProgress: func(_, _ uint64, _ int) { progress++ },
	})
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if want := []string{"192.168.1.3"}; !reflect.DeepEqual(live, want) {
		t.Fatalf("Discover live = %v, want %v", live, want)
	}
	if !reflect.DeepEqual(found, live) {
		t.Fatalf("OnFound = %v, want %v", found, live)
	}
	if progress == 0 {
		t.Fatalf("expected at least one progress callback")
	}
}

func TestDiscoverRejectsNoPorts(t *testing.T) {
	network, _ := ParseCIDR("192.168.1.0/29")
	scanner := NewScanner()
	if _, err := scanner.Discover(context.Background(), network, Options{}, Observer{}); err == nil {
		t.Fatalf("expected an error for an empty port list")
	}
}

func TestDiscoverHonoursCancellation(t *testing.T) {
	network, _ := ParseCIDR("10.0.0.0/24")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanner := &Scanner{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
	}
	live, err := scanner.Discover(ctx, network, Options{Ports: []int{80}, Concurrency: 4}, Observer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(live) != 0 {
		t.Fatalf("live = %v, want none", live)
	}
}

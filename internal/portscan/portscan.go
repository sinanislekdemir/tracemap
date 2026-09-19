// Package portscan finds open TCP and UDP ports on a host using only the Go
// standard library. It performs a TCP connect scan (or a best-effort UDP probe)
// with randomised port order, bounded concurrency and optional jitter, and can
// identify the service behind an open port by banner, HTTP or TLS probing.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scan tuning defaults.
const (
	DefaultConcurrency = 64
	DefaultTimeout     = 500 * time.Millisecond
	DefaultJitter      = 8 * time.Millisecond
	progressEvery      = 25
)

// Options controls a scan. The zero value is usable: defaults are filled in.
type Options struct {
	// Protocol is "tcp" (default) or "udp".
	Protocol string
	// Ports is the set of ports to probe. Required.
	Ports []int
	// Concurrency is the maximum number of in-flight probes.
	Concurrency int
	// Timeout is the per-port connect/response budget.
	Timeout time.Duration
	// Probe identifies the service on each open port.
	Probe bool
	// Jitter adds a random 0..Jitter delay before each probe to avoid a
	// lock-step scan signature.
	Jitter time.Duration
}

// Result describes one open port.
type Result struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Detail   string `json:"detail,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
}

// Observer receives scan progress. Every callback is optional.
type Observer struct {
	// OnOpen is invoked as soon as an open port is found.
	OnOpen func(Result)
	// OnProgress is invoked periodically with the number of ports probed and
	// the running count of open ports.
	OnProgress func(done, total, open int)
}

// Scanner probes ports. Its zero value is ready to use; the function fields
// exist so tests can substitute the dialer and resolver.
type Scanner struct {
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	ResolveIP   func(ctx context.Context, host string) ([]net.IP, error)
}

// NewScanner returns a Scanner that uses the system network stack.
func NewScanner() *Scanner {
	return &Scanner{}
}

// Scan probes opts.Ports on host and returns the open ones, sorted by port. A
// cancelled context stops the scan and returns the results gathered so far
// together with the context error.
func (s *Scanner) Scan(ctx context.Context, host string, opts Options, obs Observer) ([]Result, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("host is required")
	}

	protocol := normalizeProtocol(opts.Protocol)
	if protocol == "" {
		return nil, fmt.Errorf("unsupported protocol %q", opts.Protocol)
	}

	ports := dedupePorts(opts.Ports)
	if len(ports) == 0 {
		return nil, errors.New("no ports to scan")
	}
	if len(ports) > MaxPorts {
		ports = ports[:MaxPorts]
	}

	ip, err := s.resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > len(ports) {
		concurrency = len(ports)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	shuffled := clonePorts(ports)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	total := len(shuffled)

	var (
		mu      sync.Mutex
		results []Result
		open    int64
		done    int64
	)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

scanLoop:
	for _, port := range shuffled {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break scanLoop
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}
			if opts.Jitter > 0 && !sleepJitter(ctx, opts.Jitter) {
				return
			}

			result, found := s.scanPort(ctx, ip, host, port, protocol, timeout, opts.Probe)
			if found {
				atomic.AddInt64(&open, 1)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				if obs.OnOpen != nil {
					obs.OnOpen(result)
				}
			}

			n := atomic.AddInt64(&done, 1)
			if obs.OnProgress != nil && (n%progressEvery == 0 || int(n) == total) {
				obs.OnProgress(int(n), total, int(atomic.LoadInt64(&open)))
			}
		}(port)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Port != results[j].Port {
			return results[i].Port < results[j].Port
		}
		return results[i].Protocol < results[j].Protocol
	})
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

// scanPort probes one port and returns the result plus whether it is open.
func (s *Scanner) scanPort(ctx context.Context, ip, host string, port int, protocol string, timeout time.Duration, probe bool) (Result, bool) {
	result := Result{Port: port, Protocol: protocol, Service: ServiceName(port)}

	if protocol == "udp" {
		payload, ok := s.scanUDP(ip, port, timeout)
		if !ok {
			return Result{}, false
		}
		if probe {
			product, detail, banner := identifyUDP(port, payload)
			result.Product = product
			result.Detail = detail
			result.Banner = banner
		}
		return result, true
	}

	conn, err := s.dial(ctx, ip, port, timeout)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()

	if probe {
		dial := func() (net.Conn, error) { return s.dial(ctx, ip, port, timeout) }
		pr := probeConn(conn, host, port, dial)
		result.Product = pr.Product
		result.Banner = pr.Banner
		result.Detail = pr.Detail
		result.TLS = pr.TLS
	}
	return result, true
}

// dial opens a TCP connection to ip:port with the per-port timeout applied.
func (s *Scanner) dial(ctx context.Context, ip string, port int, timeout time.Duration) (net.Conn, error) {
	dial := s.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return dial(dctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
}

// scanUDP sends a probe datagram and returns the reply payload together with
// whether any reply arrived.
func (s *Scanner) scanUDP(ip string, port int, timeout time.Duration) ([]byte, bool) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	payload := udpProbePayload(port)
	if len(payload) == 0 {
		payload = []byte{0x00}
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, false
	}
	reply := make([]byte, n)
	copy(reply, buf[:n])
	return reply, true
}

// resolve turns host into a single address to scan, preferring IPv4.
func (s *Scanner) resolve(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}

	resolve := s.ResolveIP
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := resolve(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return ips[0].String(), nil
}

// normalizeProtocol maps user input to a supported protocol, or "".
func normalizeProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "tcp":
		return "tcp"
	case "udp":
		return "udp"
	default:
		return ""
	}
}

// dedupePorts drops invalid and duplicate port numbers, preserving order.
func dedupePorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out
}

// sleepJitter waits a random duration up to jitter, returning false if the
// context is cancelled first.
func sleepJitter(ctx context.Context, jitter time.Duration) bool {
	timer := time.NewTimer(time.Duration(rand.Int63n(int64(jitter))))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

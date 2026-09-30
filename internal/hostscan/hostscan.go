// Package hostscan enumerates IPv4 CIDR blocks and discovers live hosts by
// probing a small set of TCP ports. It uses only the Go standard library and
// deliberately does not require raw sockets or elevated privileges: a host is
// "live" when any probed port accepts a TCP connection.
package hostscan

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Discovery tuning defaults.
const (
	// DefaultHostConcurrency bounds how many hosts are probed at once.
	DefaultHostConcurrency = 48
	// DefaultPortConcurrency bounds how many ports of one host are probed at
	// once, so a host with many filtered ports does not take ports*timeout.
	DefaultPortConcurrency = 8
	// DefaultTimeout is the per-port dial budget.
	DefaultTimeout = 400 * time.Millisecond
	// progressEvery controls how often OnProgress fires.
	progressEvery = 16
)

// Options controls host discovery. The zero value is usable: defaults are
// filled in, but Ports is required.
type Options struct {
	// Ports are the TCP ports probed to decide liveness. Required.
	Ports []int
	// Concurrency is the maximum number of hosts probed at once.
	Concurrency int
	// PortConcurrency is the maximum number of ports probed per host at once.
	PortConcurrency int
	// Timeout is the per-port connect budget.
	Timeout time.Duration
}

// Observer receives discovery progress. Every callback is optional.
type Observer struct {
	// OnFound is invoked when a host answers on a port, with the first port
	// that accepted the connection.
	OnFound func(host string, openPort int)
	// OnProgress is invoked periodically with the number of hosts probed, the
	// total host count and the running count of live hosts.
	OnProgress func(done, total uint64, found int)
	// OnLog is invoked for verbose, human-readable steps.
	OnLog func(level, message string)
}

// Scanner discovers live hosts. Its zero value is ready to use; DialContext
// exists so tests can substitute the dialer.
type Scanner struct {
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewScanner returns a Scanner that uses the system network stack.
func NewScanner() *Scanner {
	return &Scanner{}
}

// ParseCIDR parses an IPv4 CIDR block such as "10.0.0.0/24" and returns its
// masked network. ok is false when input is not a CIDR (for example a bare
// hostname or IP) or is IPv6, so callers can fall back to normal handling.
func ParseCIDR(input string) (network net.IPNet, ok bool) {
	input = strings.TrimSpace(input)
	if !strings.Contains(input, "/") {
		return net.IPNet{}, false
	}
	ip, ipnet, err := net.ParseCIDR(input)
	if err != nil || ip.To4() == nil {
		return net.IPNet{}, false
	}
	base := ipnet.IP.To4()
	if base == nil {
		return net.IPNet{}, false
	}
	mask := ipnet.Mask
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}
	if len(mask) != net.IPv4len {
		return net.IPNet{}, false
	}
	return net.IPNet{IP: base, Mask: mask}, true
}

// Count returns the number of usable host addresses in network. The network and
// broadcast addresses are excluded for prefixes up to /30; /31 and /32 yield
// all of their addresses. It matches the set Each visits.
func Count(network net.IPNet) uint64 {
	ones, bits := network.Mask.Size()
	if bits != 32 || network.IP.To4() == nil {
		return 0
	}
	total := uint64(1) << uint(32-ones)
	if ones <= 30 {
		if total <= 2 {
			return 0
		}
		return total - 2
	}
	return total
}

// Each invokes fn for every usable host address in network, in ascending
// order. fn returns false to stop early. See Count for which addresses are
// visited. It streams rather than materialising the block, so it is safe for
// large prefixes.
func Each(network net.IPNet, fn func(ip string) bool) {
	base := network.IP.To4()
	if base == nil {
		return
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return
	}
	start := binary.BigEndian.Uint32(base)
	total := uint64(1) << uint(32-ones)
	last := start + uint32(total-1)

	lo, hi := start, last
	if ones <= 30 {
		if total <= 2 {
			return
		}
		lo++
		hi--
	}

	buf := make([]byte, net.IPv4len)
	for i := lo; ; i++ {
		binary.BigEndian.PutUint32(buf, i)
		if !fn(net.IP(buf).String()) {
			return
		}
		if i == hi {
			break
		}
	}
}

// Discover probes every host in network on opts.Ports and returns the live
// addresses in the order they are found. A cancelled context stops the scan
// and returns the hosts found so far together with the context error.
func (s *Scanner) Discover(ctx context.Context, network net.IPNet, opts Options, obs Observer) ([]string, error) {
	ports := dedupePorts(opts.Ports)
	if len(ports) == 0 {
		return nil, errors.New("no ports to probe")
	}
	total := Count(network)
	if total == 0 {
		return nil, errors.New("network has no usable addresses")
	}

	hostConcurrency := opts.Concurrency
	if hostConcurrency <= 0 {
		hostConcurrency = DefaultHostConcurrency
	}
	portConcurrency := opts.PortConcurrency
	if portConcurrency <= 0 {
		portConcurrency = DefaultPortConcurrency
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	var (
		mu    sync.Mutex
		live  []string
		found int64
		done  uint64
	)
	sem := make(chan struct{}, hostConcurrency)
	var wg sync.WaitGroup

	Each(network, func(host string) bool {
		if ctx.Err() != nil {
			return false
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return false
		}
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			port, ok := s.probeHost(ctx, h, ports, portConcurrency, timeout)
			if ok {
				mu.Lock()
				live = append(live, h)
				mu.Unlock()
				atomic.AddInt64(&found, 1)
				if obs.OnFound != nil {
					obs.OnFound(h, port)
				}
			}

			n := atomic.AddUint64(&done, 1)
			if obs.OnProgress != nil && (n%progressEvery == 0 || n == total) {
				obs.OnProgress(n, total, int(atomic.LoadInt64(&found)))
			}
		}(host)
		return true
	})
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return live, err
	}
	return live, nil
}

// probeHost dials each port (bounded, concurrently) and returns the first port
// that accepts a connection, stopping the rest. ok is false when none answer.
func (s *Scanner) probeHost(ctx context.Context, host string, ports []int, concurrency int, timeout time.Duration) (int, bool) {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		first int
		got   int32
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

ports:
	for _, port := range ports {
		if atomic.LoadInt32(&got) != 0 {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-probeCtx.Done():
			break ports
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			if probeCtx.Err() != nil {
				return
			}
			conn, err := s.dial(probeCtx, host, p, timeout)
			if err != nil {
				return
			}
			_ = conn.Close()
			if atomic.CompareAndSwapInt32(&got, 0, 1) {
				first = p
				cancel()
			}
		}(port)
	}
	wg.Wait()

	if atomic.LoadInt32(&got) == 0 {
		return 0, false
	}
	return first, true
}

// dial opens a TCP connection to host:port with the per-port timeout applied.
func (s *Scanner) dial(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	dial := s.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return dial(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
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

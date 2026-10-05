package portscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolScanFindsOpenPort(t *testing.T) {
	port, closeLn := listenTCP(t)
	defer closeLn()

	pool := NewPool(NewScanner(), 8)
	defer pool.Close()

	results, err := pool.Scan(context.Background(), "127.0.0.1", Options{
		Ports:   []int{port},
		Timeout: 300 * time.Millisecond,
	}, Observer{})
	if err != nil {
		t.Fatalf("pool scan error: %v", err)
	}
	if len(results) != 1 || results[0].Port != port {
		t.Fatalf("pool scan = %v, want port %d open", results, port)
	}
}

// blockingScanner returns a Scanner whose DialContext blocks until release is
// closed, tracking how many dials run at once.
func blockingScanner(release <-chan struct{}) (*Scanner, *int64, *int64) {
	var current, max int64
	scanner := &Scanner{
		ResolveIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			n := atomic.AddInt64(&current, 1)
			for {
				observed := atomic.LoadInt64(&max)
				if n <= observed || atomic.CompareAndSwapInt64(&max, observed, n) {
					break
				}
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			atomic.AddInt64(&current, -1)
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		},
	}
	return scanner, &current, &max
}

// waitForSaturation blocks until current reaches want (or the deadline passes).
func waitForSaturation(current *int64, want int64) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(current) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPoolBoundsConcurrency(t *testing.T) {
	release := make(chan struct{})
	scanner, current, max := blockingScanner(release)

	pool := NewPool(scanner, 3)
	defer pool.Close()

	ports := make([]int, 24)
	for i := range ports {
		ports[i] = 2000 + i
	}

	go func() {
		waitForSaturation(current, 3)
		close(release)
	}()

	if _, err := pool.Scan(context.Background(), "example.test", Options{
		Ports: ports, Timeout: time.Second,
	}, Observer{}); err != nil {
		t.Fatalf("pool scan error: %v", err)
	}
	if got := atomic.LoadInt64(max); got > 3 {
		t.Fatalf("max concurrent dials = %d, want <= 3", got)
	}
	if got := atomic.LoadInt64(max); got != 3 {
		t.Fatalf("max concurrent dials = %d, want the pool saturated at 3", got)
	}
}

func TestPoolConcurrentScansShareBudget(t *testing.T) {
	release := make(chan struct{})
	scanner, current, max := blockingScanner(release)

	pool := NewPool(scanner, 4)
	defer pool.Close()

	ports := make([]int, 12)
	for i := range ports {
		ports[i] = 3000 + i
	}

	go func() {
		waitForSaturation(current, 4)
		close(release)
	}()

	var wg sync.WaitGroup
	for _, host := range []string{"a.test", "b.test", "c.test"} {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			_, _ = pool.Scan(context.Background(), host, Options{Ports: ports, Timeout: time.Second}, Observer{})
		}(host)
	}
	wg.Wait()

	if got := atomic.LoadInt64(max); got > 4 {
		t.Fatalf("max concurrent dials across hosts = %d, want <= pool size 4", got)
	}
}

func TestPoolScanAfterClose(t *testing.T) {
	pool := NewPool(NewScanner(), 2)
	pool.Close()

	_, err := pool.Scan(context.Background(), "127.0.0.1", Options{Ports: []int{80}}, Observer{})
	if !errors.Is(err, errPoolClosed) {
		t.Fatalf("Scan after Close error = %v, want errPoolClosed", err)
	}
	// Close is idempotent.
	pool.Close()
}

func TestPoolScanContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	pool := NewPool(NewScanner(), 4)
	defer pool.Close()

	ports := make([]int, 300)
	for i := range ports {
		ports[i] = 20000 + i
	}
	_, err := pool.Scan(ctx, "127.0.0.1", Options{Ports: ports}, Observer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pool scan error = %v, want context.Canceled", err)
	}
}

func TestPoolReusesWorkersForManyPorts(t *testing.T) {
	// The pool is reused across two sequential scans; both must work and the
	// second must not need a new pool.
	port, closeLn := listenTCP(t)
	defer closeLn()

	pool := NewPool(NewScanner(), 4)
	defer pool.Close()

	for i := 0; i < 2; i++ {
		results, err := pool.Scan(context.Background(), "127.0.0.1", Options{
			Ports:   []int{port},
			Timeout: 300 * time.Millisecond,
		}, Observer{})
		if err != nil {
			t.Fatalf("reused pool scan %d error: %v", i, err)
		}
		if len(results) != 1 {
			t.Fatalf("reused pool scan %d = %v, want one open port", i, results)
		}
	}
}

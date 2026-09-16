package geolocator

import (
	"context"
	"sync"
	"time"
)

// defaultRatePerSecond caps remote lookups so the service is never hit more
// than twice per second.
const defaultRatePerSecond = 2

// rateLimiter spaces calls so that no more than one starts per interval. It is
// safe for concurrent use and fair in arrival order.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// newRateLimiter creates a limiter allowing perSecond calls per second. A
// non-positive rate disables limiting.
func newRateLimiter(perSecond float64) *rateLimiter {
	if perSecond <= 0 {
		return &rateLimiter{}
	}
	return &rateLimiter{interval: time.Duration(float64(time.Second) / perSecond)}
}

// wait blocks until the next slot is available or ctx is done.
func (l *rateLimiter) wait(ctx context.Context) error {
	if l.interval <= 0 {
		return nil
	}

	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	delay := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

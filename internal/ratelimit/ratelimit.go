// Package ratelimit provides a small context-aware rate limiter shared by the
// geolocation and subdomain-discovery paths.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter spaces calls so that no more than one starts per interval. It is safe
// for concurrent use and fair in arrival order.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// New returns a limiter allowing perSecond calls per second. A non-positive
// rate disables limiting.
func New(perSecond float64) *Limiter {
	if perSecond <= 0 {
		return &Limiter{}
	}
	return &Limiter{interval: time.Duration(float64(time.Second) / perSecond)}
}

// Wait blocks until the next slot is available or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
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

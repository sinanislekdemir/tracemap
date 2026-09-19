package main

import (
	"context"
	"sync"
)

// canceler owns a single cancellable operation. It guarantees that only the
// most recent run can clear the stored cancel function, so a run that finishes
// after a newer one has started cannot leave the newer run uncancellable.
// It is the shared primitive behind the trace/scan, domain-analysis and
// origin-discovery cancellation models.
type canceler struct {
	mu  sync.Mutex
	gen uint64
	fn  context.CancelFunc
}

// begin cancels any running operation, installs a fresh cancel function and
// returns the new context together with an end function. end cancels the
// context and clears the handle only when this run is still the current one.
func (c *canceler) begin(parent context.Context) (context.Context, func()) {
	c.mu.Lock()
	if c.fn != nil {
		c.fn()
	}
	c.gen++
	gen := c.gen
	ctx, cancel := context.WithCancel(parent)
	c.fn = cancel
	c.mu.Unlock()

	return ctx, func() {
		cancel()
		c.mu.Lock()
		if c.gen == gen {
			c.fn = nil
		}
		c.mu.Unlock()
	}
}

// stop cancels the running operation, if any.
func (c *canceler) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fn != nil {
		c.fn()
	}
}

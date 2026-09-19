package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestSpacesCalls(t *testing.T) {
	limiter := New(20) // one call per 50ms

	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := limiter.Wait(context.Background()); err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("3 calls took %v, want at least 100ms", elapsed)
	}
}

func TestRespectsContext(t *testing.T) {
	limiter := New(1) // one call per second
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := limiter.Wait(ctx); err == nil {
		t.Error("expected a context error")
	}
}

func TestDisabled(t *testing.T) {
	limiter := New(0)

	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := limiter.Wait(context.Background()); err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("disabled limiter took %v", elapsed)
	}
}

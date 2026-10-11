package ping

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestResolveIPv4(t *testing.T) {
	ctx := context.Background()

	ip, err := resolveIPv4(ctx, " 127.0.0.1 ")
	if err != nil {
		t.Fatalf("resolveIPv4(127.0.0.1): %v", err)
	}
	if ip.String() != "127.0.0.1" {
		t.Errorf("resolveIPv4 = %s, want 127.0.0.1", ip)
	}

	if _, err := resolveIPv4(ctx, "::1"); !errors.Is(err, ErrNoIPv4) {
		t.Errorf("resolveIPv4(::1) error = %v, want ErrNoIPv4", err)
	}
	if _, err := resolveIPv4(ctx, "   "); !errors.Is(err, ErrNoIPv4) {
		t.Errorf("resolveIPv4(blank) error = %v, want ErrNoIPv4", err)
	}
}

func TestReplyKey(t *testing.T) {
	key := replyKey(net.ParseIP("192.0.2.7"), 42)
	if !strings.HasPrefix(key, "192.0.2.7|") || !strings.HasSuffix(key, "42") {
		t.Errorf("replyKey = %q, want it to identify the address and sequence", key)
	}
	if replyKey(net.ParseIP("192.0.2.7"), 1) == replyKey(net.ParseIP("192.0.2.7"), 2) {
		t.Error("replyKey must differ per sequence number")
	}
}

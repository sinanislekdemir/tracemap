package main

import (
	"strings"

	qt "github.com/mappu/miqt/qt6"

	"traceroute/internal/hostscan"
	"traceroute/internal/portscan"
)

// newFloatingDialog creates a non-modal tool window parented to the main
// window. Parenting turns it into a transient window, which window managers on
// X11, Wayland and Windows all keep above their owner — the portable
// replacement for WindowStaysOnTopHint, which Wayland ignores outright.
func newFloatingDialog(parent *qt.QWidget) *qt.QDialog {
	return qt.NewQDialog(parent)
}

// parseBlockTarget mirrors the web frontend's cidr.ts: it recognises an IPv4
// CIDR block, optionally with a ":ports" suffix, and returns the block and the
// raw port spec. ok is false for a plain hostname/IP.
func parseBlockTarget(input string) (cidr string, ports string, ok bool) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", "", false
	}
	block := trimmed
	if colon := strings.Index(trimmed, ":"); colon >= 0 {
		block = strings.TrimSpace(trimmed[:colon])
		spec := strings.TrimSpace(trimmed[colon+1:])
		if _, err := portscan.ParsePorts(spec); err != nil {
			return "", "", false
		}
		ports = spec
	}
	if _, ok := hostscan.ParseCIDR(block); !ok {
		return "", "", false
	}
	return block, ports, true
}

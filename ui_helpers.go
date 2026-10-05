package main

import (
	"strings"

	qt "github.com/mappu/miqt/qt6"

	"traceroute/internal/hostscan"
	"traceroute/internal/portscan"
)

// newFloatingDialog creates a non-modal tool window flagged to stay above the
// main window, so the main window can never be raised over it. On compositors
// that ignore always-on-top (e.g. some Wayland setups) the flag is a no-op.
func newFloatingDialog() *qt.QDialog {
	d := qt.NewQDialog2()
	d.SetWindowFlag(qt.WindowStaysOnTopHint)
	return d
}

// keepOnTop flags an existing top-level widget to stay above the main window.
// It must be called before the widget is first shown.
func keepOnTop(w *qt.QWidget) {
	w.SetWindowFlag(qt.WindowStaysOnTopHint)
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

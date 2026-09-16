package tracerouter

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Default configuration values for a trace.
const (
	DefaultMaxHops = 30
	DefaultTimeout = 30 * time.Second
)

// Options controls how a traceroute is executed.
type Options struct {
	// MaxHops is the maximum number of hops to probe. Defaults to DefaultMaxHops.
	MaxHops int
	// Timeout is the overall wall-clock budget for the trace. Defaults to DefaultTimeout.
	Timeout time.Duration
	// ResolveNames enables reverse DNS lookups. Disabled by default for speed and
	// stable parsing.
	ResolveNames bool
}

// Runner executes the system traceroute/tracert binary and parses its output.
type Runner struct {
	// Binary optionally overrides the traceroute binary path (used in tests).
	Binary string
}

// NewRunner creates a Runner that uses the platform's traceroute binary.
func NewRunner() *Runner {
	return &Runner{}
}

// Observer receives progress updates while a trace runs. Every callback is
// optional; nil callbacks are ignored.
type Observer struct {
	// OnHop is invoked for every hop as soon as its line is produced.
	OnHop func(Hop)
	// OnTarget is invoked once, with the resolved target address, as soon as
	// the traceroute header is parsed.
	OnTarget func(ip string)
}

// Execute runs a traceroute and returns the parsed hops once it completes.
func (r *Runner) Execute(ctx context.Context, target string, opts Options) ([]Hop, error) {
	var hops []Hop
	err := r.ExecuteStream(ctx, target, opts, Observer{OnHop: func(h Hop) {
		hops = append(hops, h)
	}})
	if err != nil {
		return hops, err
	}
	return hops, nil
}

// ExecuteStream runs a traceroute and reports progress through obs as output is
// produced, which allows results to be streamed to a client.
func (r *Runner) ExecuteStream(ctx context.Context, target string, opts Options, obs Observer) error {
	onHop := obs.OnHop
	if onHop == nil {
		onHop = func(Hop) {}
	}

	binary, args, timeout, err := r.build(target, opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("traceroute stdout: %w", err)
	}

	// Capture stderr so failures carry the real reason (e.g. "Name or service
	// not known") instead of just the exit status. exec drains it concurrently,
	// so the child cannot block on a full pipe.
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("traceroute command failed: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	targetSeen := false
	for scanner.Scan() {
		line := scanner.Text()
		if !targetSeen && obs.OnTarget != nil {
			if ip, ok := ParseTarget(line); ok {
				targetSeen = true
				obs.OnTarget(ip)
				continue
			}
		}
		hop, ok := parseHopLine(line)
		if !ok {
			continue
		}
		onHop(hop)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if msg := firstLine(stderrBuf.String()); msg != "" {
			return fmt.Errorf("traceroute: %s", msg)
		}
		return fmt.Errorf("traceroute command failed: %w", err)
	}
	return nil
}

// firstLine returns the first non-empty line of s, trimmed. It is used to turn
// raw traceroute stderr into a single readable error message.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// build validates the target and produces the platform-specific command line.
func (r *Runner) build(target string, opts Options) (binary string, args []string, timeout time.Duration, err error) {
	if err := validateTarget(target); err != nil {
		return "", nil, 0, err
	}

	maxHops := opts.MaxHops
	if maxHops <= 0 {
		maxHops = DefaultMaxHops
	}
	timeout = opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	binary = r.Binary
	if binary == "" {
		if runtime.GOOS == "windows" {
			binary = "tracert"
		} else {
			binary = "traceroute"
		}
	}

	if runtime.GOOS == "windows" {
		// -d: do not resolve addresses, -h: max hops, -w: per-probe timeout (ms).
		args = []string{"-d", "-h", strconv.Itoa(maxHops), "-w", strconv.Itoa(probeTimeoutMS(timeout))}
		if opts.ResolveNames {
			args = args[1:] // drop -d when reverse lookups are wanted
		}
	} else {
		// -n: do not resolve addresses, -m: max hops, -w: per-probe wait (seconds),
		// -q: probes per hop.
		args = []string{"-n", "-m", strconv.Itoa(maxHops), "-w", strconv.Itoa(probeTimeoutSeconds(timeout)), "-q", "3"}
		if opts.ResolveNames {
			args = args[1:] // drop -n when reverse lookups are wanted
		}
	}
	args = append(args, target)

	return binary, args, timeout, nil
}

func probeTimeoutSeconds(timeout time.Duration) int {
	seconds := int(math.Ceil(timeout.Seconds() / 3))
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}

func probeTimeoutMS(timeout time.Duration) int {
	ms := int(timeout.Milliseconds() / 3)
	if ms < 1 {
		ms = 1
	}
	return ms
}

// targetPattern allows hostnames, IPv4 and IPv6 literals.
var targetPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._:\-]*[A-Za-z0-9])?$`)

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if len(target) > 253 {
		return fmt.Errorf("target is too long")
	}
	if !targetPattern.MatchString(target) {
		return fmt.Errorf("invalid target %q", target)
	}
	return nil
}

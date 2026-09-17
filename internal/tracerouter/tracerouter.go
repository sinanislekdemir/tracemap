package tracerouter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
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
	parser := &hopParser{onHop: onHop}
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
		parser.feed(line)
	}
	parser.flush()

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
		binary, err = discoverBinary(runtime.GOOS)
		if err != nil {
			return "", nil, 0, err
		}
	}

	args = argsFor(toolFromBinary(binary), maxHops, opts.ResolveNames, timeout)
	args = append(args, target)

	return binary, args, timeout, nil
}

// tool identifies which traceroute implementation a binary is, so the right
// flags and output format can be used.
type tool int

const (
	toolTraceroute tool = iota
	toolTracert
	toolTracepath
	toolMtr
)

// binaryCandidate is one executable to look for, by name on PATH and by
// explicit absolute path. The absolute paths matter for GUI apps launched from
// a desktop entry, whose PATH is often minimal and omits /usr/sbin.
type binaryCandidate struct {
	name  string
	paths []string
}

// MissingToolError reports that none of the supported traceroute tools are
// installed. Tools lists the executable names that were searched for.
type MissingToolError struct {
	Tools []string
}

func (e *MissingToolError) Error() string {
	return "no traceroute tool found: install one of " + strings.Join(e.Tools, ", ")
}

// IsMissingTool reports whether err was caused by no traceroute tool being
// installed on the system.
func IsMissingTool(err error) bool {
	var missing *MissingToolError
	return errors.As(err, &missing)
}

// Detect locates a usable traceroute tool for the current platform. It returns
// a *MissingToolError when none is installed.
func Detect() (string, error) {
	return discoverBinary(runtime.GOOS)
}

// InstallHint returns a platform-specific suggestion for installing a
// traceroute tool, shown to the user when Detect fails.
func InstallHint() string {
	switch runtime.GOOS {
	case "windows":
		return "tracert is included with Windows. Restore C:\\Windows\\System32\\tracert.exe, or reinstall Windows."
	case "darwin":
		return "Install it with Homebrew: brew install traceroute — or install mtr with brew install mtr."
	default:
		return "Install one with your package manager: sudo apt install traceroute (Debian/Ubuntu), sudo dnf install traceroute (Fedora), or sudo pacman -S traceroute (Arch)."
	}
}

// discoverBinary finds a usable traceroute tool for goos, preferring the
// canonical traceroute/tracert and falling back to tracepath or mtr.
func discoverBinary(goos string) (string, error) {
	candidates := candidatesFor(goos)
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate.name); err == nil {
			return path, nil
		}
		for _, path := range candidate.paths {
			if isExecutable(path) {
				return path, nil
			}
		}
	}

	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.name)
	}
	return "", &MissingToolError{Tools: names}
}

// candidatesFor lists the tools to try, in priority order.
func candidatesFor(goos string) []binaryCandidate {
	if goos == "windows" {
		var paths []string
		if root := os.Getenv("SystemRoot"); root != "" {
			paths = append(paths, filepath.Join(root, "System32", "tracert.exe"))
		}
		return []binaryCandidate{{name: "tracert", paths: paths}}
	}
	return []binaryCandidate{
		{name: "traceroute", paths: unixPaths("traceroute")},
		{name: "tracepath", paths: unixPaths("tracepath")},
		{name: "mtr", paths: unixPaths("mtr")},
	}
}

// unixPaths returns the conventional install locations for a Unix tool.
func unixPaths(name string) []string {
	return []string{
		"/usr/bin/" + name,
		"/bin/" + name,
		"/usr/sbin/" + name,
		"/sbin/" + name,
		"/usr/local/bin/" + name,
		"/usr/local/sbin/" + name,
	}
}

// toolFromBinary infers the implementation from the executable's base name.
// Both path separators are handled so the detection is testable regardless of
// the host platform.
func toolFromBinary(path string) tool {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(strings.ToLower(base), ".exe")
	switch {
	case base == "tracert":
		return toolTracert
	case base == "tracepath":
		return toolTracepath
	case base == "mtr":
		return toolMtr
	default:
		return toolTraceroute
	}
}

// argsFor builds the probe arguments for a tool. maxHops, the optional
// per-probe wait and the probe count are expressed with each tool's own flags.
func argsFor(t tool, maxHops int, resolveNames bool, timeout time.Duration) []string {
	switch t {
	case toolTracert:
		args := []string{"-h", strconv.Itoa(maxHops), "-w", strconv.Itoa(probeTimeoutMS(timeout))}
		if !resolveNames {
			args = append([]string{"-d"}, args...)
		}
		return args
	case toolTracepath:
		args := []string{"-m", strconv.Itoa(maxHops)}
		if !resolveNames {
			args = append([]string{"-n"}, args...)
		}
		return args
	case toolMtr:
		args := []string{"-r", "-c", "1", "-m", strconv.Itoa(maxHops)}
		if !resolveNames {
			args = append([]string{"-n"}, args...)
		}
		return args
	default: // traceroute
		args := []string{"-m", strconv.Itoa(maxHops), "-w", strconv.Itoa(probeTimeoutSeconds(timeout)), "-q", "3"}
		if !resolveNames {
			args = append([]string{"-n"}, args...)
		}
		return args
	}
}

// isExecutable reports whether path is an existing, executable file.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode()&0o111 != 0
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

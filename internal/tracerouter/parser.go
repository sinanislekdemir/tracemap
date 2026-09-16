package tracerouter

import (
	"bufio"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Hop describes a single hop in a traceroute.
type Hop struct {
	Number int
	IP     string
	RTTs   []time.Duration
}

// Responded reports whether the hop produced at least one reply.
func (h Hop) Responded() bool {
	return h.IP != ""
}

// BestRTT returns the lowest RTT observed for the hop, or 0 when unresponsive.
func (h Hop) BestRTT() time.Duration {
	if len(h.RTTs) == 0 {
		return 0
	}
	best := h.RTTs[0]
	for _, rtt := range h.RTTs[1:] {
		if rtt < best {
			best = rtt
		}
	}
	return best
}

// merge folds a repeated line for the same hop into h. tracepath prints one
// line per probe, so a single hop can arrive several times; the first line may
// also carry no address when it is a "no reply" marker.
func (h *Hop) merge(other Hop) {
	h.RTTs = append(h.RTTs, other.RTTs...)
	if h.IP == "" {
		h.IP = other.IP
	}
}

// Line formats understood by the parser.
var (
	// traceroute (Unix) and tracert (Windows): " 1  host 1.2 ms ...".
	hopLine = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	// tracepath: " 1?: [LOCALHOST] pmtu 1500" / " 1: host 0.2ms".
	tracepathLine = regexp.MustCompile(`^\s*(\d+)\??:\s*(.*)$`)
	// mtr report: "  1.|-- host 0.0% 1 0.3 0.3 0.3 0.3 0.0".
	mtrLine = regexp.MustCompile(`^\s*(\d+)\.\s*\|\-\-\s+(.*)$`)
)

// rttValue matches a latency measurement such as "12.34 ms" or "0.282ms".
var rttValue = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*ms`)

// Target address patterns from the traceroute/tracert header line.
var (
	unixTarget = regexp.MustCompile(`traceroute to \S+ \(([0-9a-fA-F:.]+)\)`)
	winTarget  = regexp.MustCompile(`(?i)tracing route to \S+ \[([0-9a-fA-F:.]+)\]`)
)

// ParseTarget extracts the resolved target address from a traceroute header
// line. It understands the Unix ("traceroute to host (1.2.3.4), ...") and
// Windows ("Tracing route to host [1.2.3.4] ...") formats, returning ok=false
// when the line carries no resolved address.
func ParseTarget(line string) (string, bool) {
	if m := unixTarget.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	if m := winTarget.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

// Parse converts raw traceroute, tracert, tracepath or mtr output into an
// ordered list of hops.
//
// It understands the Unix format
//
//	1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms
//
// the Windows format
//
//	1     1 ms     1 ms     1 ms  192.168.1.1
//
// the tracepath format (one line per probe)
//
//	1:  192.168.1.1  0.282ms
//
// and the mtr report format
//
//	1.|-- 192.168.1.1  0.0%  1  0.3  0.3  0.3  0.3  0.0
//
// as well as unresponsive hops ("* * *", "no reply", "???"). Non-hop lines
// (headers, summaries) are ignored.
func Parse(output string) []Hop {
	var hops []Hop
	parser := &hopParser{onHop: func(h Hop) { hops = append(hops, h) }}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		parser.feed(scanner.Text())
	}
	parser.flush()
	return hops
}

// hopParser assembles hops from a line stream, merging repeated lines that
// belong to the same hop number before emitting them. A hop is only emitted
// once a higher (or lower) number is seen, or at flush time, so tracepath's
// repeated per-probe lines collapse into a single hop.
type hopParser struct {
	onHop   func(Hop)
	pending *Hop
}

func (p *hopParser) feed(line string) {
	hop, ok := parseHopLine(line)
	if !ok {
		return
	}
	if p.pending != nil && hop.Number == p.pending.Number {
		p.pending.merge(hop)
		return
	}
	p.emit()
	p.pending = &hop
}

func (p *hopParser) flush() {
	p.emit()
}

func (p *hopParser) emit() {
	if p.pending == nil {
		return
	}
	if p.onHop != nil {
		p.onHop(*p.pending)
	}
	p.pending = nil
}

// parseHopLine recognises a single hop line in any of the supported formats.
func parseHopLine(line string) (Hop, bool) {
	if m := hopLine.FindStringSubmatch(line); m != nil {
		return buildHop(m[1], m[2], false), true
	}
	if m := tracepathLine.FindStringSubmatch(line); m != nil {
		return buildHop(m[1], m[2], false), true
	}
	if m := mtrLine.FindStringSubmatch(line); m != nil {
		return buildHop(m[1], m[2], true), true
	}
	return Hop{}, false
}

// buildHop extracts the hop number, RTTs and address from the text following
// the hop number. mtr report lines carry their RTT as a bare column instead of
// an "ms"-suffixed value.
func buildHop(numberStr, rest string, mtr bool) Hop {
	number, _ := strconv.Atoi(numberStr)
	hop := Hop{Number: number}

	for _, m := range rttValue.FindAllStringSubmatch(rest, -1) {
		ms, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		hop.RTTs = append(hop.RTTs, time.Duration(ms*float64(time.Millisecond)))
	}
	if mtr && len(hop.RTTs) == 0 {
		if ms, ok := mtrLastRTT(rest); ok {
			hop.RTTs = append(hop.RTTs, time.Duration(ms*float64(time.Millisecond)))
		}
	}

	for _, field := range strings.Fields(rest) {
		candidate := strings.Trim(field, "()")
		if ip := net.ParseIP(candidate); ip != nil {
			hop.IP = candidate
			break
		}
	}

	return hop
}

// mtrLastRTT reads the "Last" column from an mtr report line. The columns after
// the host are Loss% Snt Last Avg Best Wrst StDev; a fully lost hop is treated
// as having no RTT.
func mtrLastRTT(rest string) (float64, bool) {
	fields := strings.Fields(rest)
	if len(fields) < 4 {
		return 0, false
	}
	values := fields[1:] // drop the host
	if strings.HasPrefix(values[0], "100") {
		return 0, false
	}
	ms, err := strconv.ParseFloat(values[2], 64)
	if err != nil {
		return 0, false
	}
	return ms, true
}

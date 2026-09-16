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

// hopLine matches the leading hop number of a traceroute/tracert line.
var hopLine = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)

// rttValue matches a latency measurement such as "12.34 ms".
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

// Parse converts raw traceroute or tracert output into an ordered list of hops.
//
// It understands both the Unix format
//
//	1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms
//
// and the Windows format
//
//	1     1 ms     1 ms     1 ms  192.168.1.1
//
// as well as unresponsive hops ("* * *"). Non-hop lines (headers, summaries)
// are ignored.
func Parse(output string) []Hop {
	var hops []Hop
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		hop, ok := parseHopLine(scanner.Text())
		if !ok {
			continue
		}
		hops = append(hops, hop)
	}
	return hops
}

func parseHopLine(line string) (Hop, bool) {
	match := hopLine.FindStringSubmatch(line)
	if match == nil {
		return Hop{}, false
	}

	number, err := strconv.Atoi(match[1])
	if err != nil {
		return Hop{}, false
	}

	rest := strings.TrimSpace(match[2])
	hop := Hop{Number: number}

	for _, m := range rttValue.FindAllStringSubmatch(rest, -1) {
		ms, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		hop.RTTs = append(hop.RTTs, time.Duration(ms*float64(time.Millisecond)))
	}

	for _, field := range strings.Fields(rest) {
		candidate := strings.Trim(field, "()")
		if ip := net.ParseIP(candidate); ip != nil {
			hop.IP = candidate
			break
		}
	}

	return hop, true
}

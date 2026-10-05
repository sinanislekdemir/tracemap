package main

import (
	"math"

	"traceroute/internal/geolocator"
	"traceroute/internal/mapdata"
)

// traceColors are the distinct, dark-background friendly colours assigned to
// traces in order.
var traceColors = []string{
	"#2dd4ef", "#f5b642", "#a78bfa", "#3ddc97", "#ff6b6b", "#f472b6",
	"#60a5fa", "#facc15", "#4ade80", "#fb923c", "#c084fc", "#38bdf8",
}

func traceColor(i int) string { return traceColors[i%len(traceColors)] }

func correlationColor(count int) string {
	switch {
	case count >= 4:
		return "#ff6b6b"
	case count >= 2:
		return "#f5b642"
	default:
		return "#38bdf8"
	}
}

// hopData is one rendered hop.
type hopData struct {
	Hop      int
	IP       string
	RTTMs    float64
	HasRTT   bool
	Geo      *geolocator.GeoData
	IsTarget bool
}

// traceState is one trace shown on the map and in the sidebar.
type traceState struct {
	ID        int
	Label     string
	Kind      string
	IP        string
	Color     string
	TargetIP  string
	TargetGeo *geolocator.GeoData
	Hops      []hopData
	Error     string
	Done      bool
}

func isLocated(g *geolocator.GeoData) bool {
	if g == nil || !g.Resolved {
		return false
	}
	if math.IsNaN(g.Lat) || math.IsNaN(g.Lon) || math.IsInf(g.Lat, 0) || math.IsInf(g.Lon, 0) {
		return false
	}
	return g.Lat != 0 || g.Lon != 0
}

// buildDisplayHops appends/marks the resolved target IP as the final entry.
func buildDisplayHops(t *traceState) []hopData {
	if t.TargetIP == "" {
		return t.Hops
	}
	match := -1
	for i, h := range t.Hops {
		if h.IP == t.TargetIP {
			match = i
		}
	}
	if match != -1 {
		out := make([]hopData, len(t.Hops))
		copy(out, t.Hops)
		out[match].IsTarget = true
		return out
	}
	next := 1
	for _, h := range t.Hops {
		if h.Hop+1 > next {
			next = h.Hop + 1
		}
	}
	nh := hopData{Hop: next, IP: t.TargetIP, IsTarget: true}
	if t.TargetGeo != nil {
		g := *t.TargetGeo
		nh.Geo = &g
	}
	return append(append([]hopData{}, t.Hops...), nh)
}

func merc(lat, lon float64) (float64, float64) { return mapdata.Mercator(lat, lon) }

// curveSegment is a quadratic bezier bowing consistently to one side.
func curveSegment(a, b [2]float64) [][2]float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	const bow = 0.16
	cx := (a[0]+b[0])/2 - dy*bow
	cy := (a[1]+b[1])/2 + dx*bow
	const steps = 16
	out := make([][2]float64, 0, steps+1)
	for i := 0; i <= steps; i++ {
		t := float64(i) / steps
		mt := 1 - t
		out = append(out, [2]float64{
			mt*mt*a[0] + 2*mt*t*cx + t*t*b[0],
			mt*mt*a[1] + 2*mt*t*cy + t*t*b[1],
		})
	}
	return out
}

func buildRoute(pts [][2]float64) [][2]float64 {
	if len(pts) < 2 {
		return pts
	}
	route := [][2]float64{pts[0]}
	for i := 1; i < len(pts); i++ {
		seg := curveSegment(pts[i-1], pts[i])
		route = append(route, seg[1:]...)
	}
	return route
}

// correlatedHop is a deduplicated hop across the selected traces.
type correlatedHop struct {
	IP       string
	Count    int
	Paths    int
	Geo      *geolocator.GeoData
	IsTarget bool
	Pos      [2]float64
	Labels   []string
}

// correlate merges the located hops of the given traces into deduplicated
// points, counting revisits and distinct paths.
func correlate(traces []*traceState) []correlatedHop {
	type acc struct {
		correlatedHop
		labelSet map[string]bool
	}
	order := []string{}
	byIP := map[string]*acc{}
	for _, t := range traces {
		for _, h := range buildDisplayHops(t) {
			if !isLocated(h.Geo) {
				continue
			}
			a := byIP[h.IP]
			if a == nil {
				x, y := merc(h.Geo.Lat, h.Geo.Lon)
				a = &acc{correlatedHop: correlatedHop{IP: h.IP, Geo: h.Geo, Pos: [2]float64{x, y}}, labelSet: map[string]bool{}}
				byIP[h.IP] = a
				order = append(order, h.IP)
			}
			a.Count++
			if !a.labelSet[t.Label] {
				a.labelSet[t.Label] = true
				a.Paths++
				a.Labels = append(a.Labels, t.Label)
			}
			if h.IsTarget {
				a.IsTarget = true
			}
		}
	}
	out := make([]correlatedHop, 0, len(order))
	for _, ip := range order {
		out = append(out, byIP[ip].correlatedHop)
	}
	return out
}

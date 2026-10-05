package mapdata

import (
	"encoding/json"
	"fmt"
)

// Minimal TopoJSON decoding, enough for the world-atlas country/land topology.

type topoTransform struct {
	Scale     [2]float64 `json:"scale"`
	Translate [2]float64 `json:"translate"`
}

type topoGeometry struct {
	Type       string          `json:"type"`
	Arcs       json.RawMessage `json:"arcs"`
	Properties topoProperties  `json:"properties"`
	Geometries []topoGeometry  `json:"geometries"`
}

type topoProperties struct {
	Name string `json:"name"`
}

type topology struct {
	Transform topoTransform           `json:"transform"`
	Arcs      [][][2]int              `json:"arcs"`
	Objects   map[string]topoGeometry `json:"objects"`
}

func parseTopology(raw []byte) (*topology, error) {
	var topo topology
	if err := json.Unmarshal(raw, &topo); err != nil {
		return nil, fmt.Errorf("mapdata: parse topology: %w", err)
	}
	if len(topo.Arcs) == 0 {
		return nil, fmt.Errorf("mapdata: topology has no arcs")
	}
	return &topo, nil
}

func (t *topology) object(name string) (topoGeometry, bool) {
	g, ok := t.Objects[name]
	return g, ok
}

// absoluteArcs decodes every arc into absolute lon/lat points.
func (t *topology) absoluteArcs() [][]Point {
	out := make([][]Point, len(t.Arcs))
	for i, arc := range t.Arcs {
		x, y := 0, 0
		pts := make([]Point, len(arc))
		for j, p := range arc {
			x += p[0]
			y += p[1]
			pts[j] = Point{
				Lon: float64(x)*t.Transform.Scale[0] + t.Transform.Translate[0],
				Lat: float64(y)*t.Transform.Scale[1] + t.Transform.Translate[1],
			}
		}
		out[i] = pts
	}
	return out
}

func (g topoGeometry) name() string { return g.Properties.Name }

func (g topoGeometry) geometries() []topoGeometry {
	if g.Type == "GeometryCollection" {
		return g.Geometries
	}
	return []topoGeometry{g}
}

// allPolygons decodes a geometry (or collection) into polygons.
func (g topoGeometry) allPolygons(abs [][]Point) []Polygon {
	switch g.Type {
	case "Polygon":
		var arcs [][]int
		_ = json.Unmarshal(g.Arcs, &arcs)
		return []Polygon{{Rings: ringsFromArcs(abs, arcs)}}
	case "MultiPolygon":
		var arcs [][][]int
		_ = json.Unmarshal(g.Arcs, &arcs)
		out := make([]Polygon, 0, len(arcs))
		for _, poly := range arcs {
			out = append(out, Polygon{Rings: ringsFromArcs(abs, poly)})
		}
		return out
	case "GeometryCollection":
		var out []Polygon
		for _, sub := range g.Geometries {
			out = append(out, sub.allPolygons(abs)...)
		}
		return out
	default:
		return nil
	}
}

// ringsFromArcs materialises one polygon's rings; each ring is the
// concatenation of its (possibly reversed) arcs.
func ringsFromArcs(abs [][]Point, rings [][]int) []Ring {
	out := make([]Ring, 0, len(rings))
	for _, idxs := range rings {
		var ring Ring
		for _, idx := range idxs {
			ring = append(ring, ringFromArc(abs, idx)...)
		}
		out = append(out, ring)
	}
	return out
}

// ringFromArc follows a (possibly negative/reversed) arc index.
func ringFromArc(abs [][]Point, idx int) Ring {
	reversed := idx < 0
	if reversed {
		idx = -idx - 1
	}
	if idx < 0 || idx >= len(abs) {
		return nil
	}
	arc := abs[idx]
	ring := make(Ring, len(arc))
	if reversed {
		for i := range arc {
			ring[i] = arc[len(arc)-1-i]
		}
	} else {
		copy(ring, arc)
	}
	return ring
}

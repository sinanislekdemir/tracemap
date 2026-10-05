package mapdata

import "math"

// Antimeridian handling. Natural Earth ships Fiji, Russia and Antarctica as
// rings that cross ±180°, which would otherwise draw as a band across the map.
// We unwrap, clip and re-split those rings so every coordinate stays inside
// [-180, 180]. This mirrors the algorithm the web frontend used.

const (
	lonMin  = -180.0
	lonMax  = 180.0
	latMin  = -90.0
	latMax  = 90.0
	epsilon = 1e-9
)

func unwrapRing(r Ring) Ring {
	pts := r
	if len(pts) > 1 {
		pts = pts[:len(pts)-1]
	}
	if len(pts) == 0 {
		return nil
	}
	out := make(Ring, 0, len(pts))
	out = append(out, pts[0])
	for i := 1; i < len(pts); i++ {
		lon := pts[i].Lon
		prev := out[len(out)-1].Lon
		for lon-prev > 180 {
			lon -= 360
		}
		for prev-lon > 180 {
			lon += 360
		}
		out = append(out, Point{Lon: lon, Lat: pts[i].Lat})
	}
	return out
}

func shiftedRing(r Ring, shift float64) Ring {
	if shift == 0 {
		return r
	}
	out := make(Ring, len(r))
	for i, p := range r {
		out[i] = Point{Lon: p.Lon + shift, Lat: p.Lat}
	}
	return out
}

func intersectLon(a, b Point, lon float64) Point {
	t := (lon - a.Lon) / (b.Lon - a.Lon)
	return Point{Lon: lon, Lat: a.Lat + t*(b.Lat-a.Lat)}
}

func intersectLat(a, b Point, lat float64) Point {
	t := (lat - a.Lat) / (b.Lat - a.Lat)
	return Point{Lon: a.Lon + t*(b.Lon-a.Lon), Lat: lat}
}

func clipRing(r Ring, inside func(Point) bool, intersect func(a, b Point) Point) Ring {
	if len(r) == 0 {
		return nil
	}
	out := make(Ring, 0, len(r))
	for i := range r {
		cur := r[i]
		prev := r[(i+len(r)-1)%len(r)]
		curIn := inside(cur)
		prevIn := inside(prev)
		if curIn {
			if !prevIn {
				out = append(out, intersect(prev, cur))
			}
			out = append(out, cur)
		} else if prevIn {
			out = append(out, intersect(prev, cur))
		}
	}
	return out
}

func clipRect(r Ring) Ring {
	out := r
	out = clipRing(out, func(p Point) bool { return p.Lon >= lonMin }, func(a, b Point) Point { return intersectLon(a, b, lonMin) })
	out = clipRing(out, func(p Point) bool { return p.Lon <= lonMax }, func(a, b Point) Point { return intersectLon(a, b, lonMax) })
	out = clipRing(out, func(p Point) bool { return p.Lat >= latMin }, func(a, b Point) Point { return intersectLat(a, b, latMin) })
	out = clipRing(out, func(p Point) bool { return p.Lat <= latMax }, func(a, b Point) Point { return intersectLat(a, b, latMax) })
	return out
}

func closeRing(r Ring) Ring {
	out := make(Ring, 0, len(r)+1)
	for _, p := range r {
		if last := lastOf(out); last != nil && math.Abs(last.Lon-p.Lon) <= epsilon && math.Abs(last.Lat-p.Lat) <= epsilon {
			continue
		}
		out = append(out, p)
	}
	if len(out) >= 2 {
		first := out[0]
		last := out[len(out)-1]
		if math.Abs(first.Lon-last.Lon) > epsilon || math.Abs(first.Lat-last.Lat) > epsilon {
			out = append(out, first)
		}
	}
	return out
}

func lastOf(r Ring) *Point {
	if len(r) == 0 {
		return nil
	}
	return &r[len(r)-1]
}

func ringArea(r Ring) float64 {
	var area float64
	for i, j := 0, len(r)-1; i < len(r); j, i = i, i+1 {
		area += r[j].Lon*r[i].Lat - r[i].Lon*r[j].Lat
	}
	return math.Abs(area) / 2
}

// splitPolygon splits one polygon (exterior first, then holes) into
// antimeridian-safe polygons.
func splitPolygon(rings []Ring) []Polygon {
	unwrapped := make([]Ring, len(rings))
	for i, r := range rings {
		unwrapped[i] = unwrapRing(r)
	}
	if len(unwrapped) == 0 {
		return nil
	}
	exterior := unwrapped[0]
	if len(exterior) < 3 {
		return nil
	}

	minLon, maxLon := math.Inf(1), math.Inf(-1)
	for _, p := range exterior {
		if p.Lon < minLon {
			minLon = p.Lon
		}
		if p.Lon > maxLon {
			maxLon = p.Lon
		}
	}

	firstShift := math.Ceil((lonMin - maxLon) / 360)
	lastShift := math.Floor((lonMax - minLon) / 360)
	var out []Polygon

	for k := firstShift; k <= lastShift; k++ {
		shift := k * 360
		outer := closeRing(clipRect(shiftedRing(exterior, shift)))
		if len(outer) < 4 || ringArea(outer) < epsilon {
			continue
		}
		holes := make([]Ring, 0, len(unwrapped)-1)
		for h := 1; h < len(unwrapped); h++ {
			hole := closeRing(clipRect(shiftedRing(unwrapped[h], shift)))
			if len(hole) >= 4 && ringArea(hole) >= epsilon {
				holes = append(holes, hole)
			}
		}
		out = append(out, Polygon{Rings: append([]Ring{outer}, holes...)})
	}
	return out
}

// splitAntimeridian splits every polygon, flattening the results.
func splitAntimeridian(polys []Polygon) []Polygon {
	var out []Polygon
	for _, p := range polys {
		out = append(out, splitPolygon(p.Rings)...)
	}
	return out
}

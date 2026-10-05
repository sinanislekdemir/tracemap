package mapdata

import (
	"math"
	"testing"
)

func TestLoad(t *testing.T) {
	w, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(w.Land) == 0 {
		t.Fatal("no land polygons")
	}
	if len(w.Countries) < 150 {
		t.Fatalf("countries = %d, want >= 150", len(w.Countries))
	}
	if len(w.Cities) < 100 {
		t.Fatalf("cities = %d, want >= 100", len(w.Cities))
	}
	for _, p := range w.Land {
		checkPolygon(t, p)
	}
	for _, c := range w.Countries {
		for _, p := range c.Polygons {
			checkPolygon(t, p)
		}
	}
}

func checkPolygon(t *testing.T, p Polygon) {
	t.Helper()
	for _, r := range p.Rings {
		for _, pt := range r {
			if pt.Lon < -180.001 || pt.Lon > 180.001 || pt.Lat < -90.001 || pt.Lat > 90.001 {
				t.Fatalf("out-of-range coordinate %v", pt)
			}
		}
	}
}

func TestMercator(t *testing.T) {
	x, y := Mercator(0, 0)
	if math.Abs(x-0.5) > 1e-9 || math.Abs(y-0.5) > 1e-9 {
		t.Fatalf("Mercator(0,0) = %v,%v want 0.5,0.5", x, y)
	}
	if _, yN := Mercator(85, 0); yN >= 0.5 {
		t.Fatalf("Mercator(85,0).y = %v, want < 0.5", yN)
	}
}

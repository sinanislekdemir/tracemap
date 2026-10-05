package mapview

import (
	"math"
	"testing"

	"traceroute/internal/mapdata"
)

func TestMercatorLatInvertsMercator(t *testing.T) {
	for _, lat := range []float64{-60, -30, -1, 0, 12.5, 45, 60} {
		_, y := mapdata.Mercator(lat, 0)
		if got := mercatorLat(y); math.Abs(got-lat) > 1e-6 {
			t.Errorf("mercatorLat(Mercator(%v)) = %v, want %v", lat, got, lat)
		}
	}
}

func TestNiceDistance(t *testing.T) {
	tests := map[float64]float64{
		0:    0,
		90:   100,
		1100: 2000,
		4500: 5000,
		9000: 10000,
	}
	for in, want := range tests {
		if got := niceDistance(in); got != want {
			t.Errorf("niceDistance(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestFormatDistance(t *testing.T) {
	tests := map[float64]string{
		500:  "500 m",
		2000: "2 km",
		1500: "1.5 km",
	}
	for in, want := range tests {
		if got := formatDistance(in); got != want {
			t.Errorf("formatDistance(%v) = %q, want %q", in, got, want)
		}
	}
}

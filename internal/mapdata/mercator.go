package mapdata

import "math"

// Mercator projects WGS84 coordinates to normalized Web-Mercator [0,1] space
// (as used by slippy maps). Multiply by TileSize*2^zoom to get pixels.
func Mercator(lat, lon float64) (x, y float64) {
	x = (lon + 180) / 360
	rad := lat * math.Pi / 180
	s := math.Sin(rad)
	y = 0.5 - math.Log((1+s)/(1-s))/(4*math.Pi)
	return x, y
}

// TileSize is the nominal tile edge in pixels (matches the web convention).
const TileSize = 256.0

// MaxZoom bounds how far the map can be zoomed in.
const MaxZoom = 8.0

// WorldPixels is the edge length, in scene pixels, of the world at MaxZoom.
const WorldPixels = TileSize * (1 << uint(MaxZoom))

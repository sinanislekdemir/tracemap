// Package mapdata loads the embedded, offline Natural Earth basemap (countries,
// land and major cities) and provides the Web-Mercator projection used to draw
// it. Nothing here touches the network.
package mapdata

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed data/countries-50m.json data/cities.json
var files embed.FS

// Point is a WGS84 longitude/latitude pair.
type Point struct {
	Lon float64
	Lat float64
}

// Ring is a closed sequence of points.
type Ring []Point

// Polygon is an exterior ring followed by zero or more hole rings.
type Polygon struct {
	Rings []Ring
}

// Country is a named country and its (antimeridian-split) polygons.
type Country struct {
	Name     string
	Polygons []Polygon
}

// City is a reference city drawn on the basemap.
type City struct {
	Name      string  `json:"name"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	Pop       int64   `json:"pop"`
	WorldCity bool    `json:"worldcity"`
	Rank      int     `json:"rank"`
}

// World is the fully-loaded, antimeridian-safe basemap.
type World struct {
	Land      []Polygon
	Countries []Country
	Cities    []City
}

// LandPolygons flattens the land polygons for drawing.
func (w *World) LandPolygons() []Polygon { return w.Land }

// Load parses the embedded basemap. It is called once at startup.
func Load() (*World, error) {
	raw, err := files.ReadFile("data/countries-50m.json")
	if err != nil {
		return nil, fmt.Errorf("mapdata: read countries: %w", err)
	}
	topo, err := parseTopology(raw)
	if err != nil {
		return nil, err
	}
	abs := topo.absoluteArcs()

	w := &World{}

	land, ok := topo.object("land")
	if !ok {
		return nil, fmt.Errorf("mapdata: land object missing")
	}
	w.Land = splitAntimeridian(land.allPolygons(abs))

	countries, ok := topo.object("countries")
	if !ok {
		return nil, fmt.Errorf("mapdata: countries object missing")
	}
	for _, g := range countries.geometries() {
		polys := splitAntimeridian(g.allPolygons(abs))
		if len(polys) == 0 {
			continue
		}
		w.Countries = append(w.Countries, Country{Name: g.name(), Polygons: polys})
	}

	cityRaw, err := files.ReadFile("data/cities.json")
	if err != nil {
		return nil, fmt.Errorf("mapdata: read cities: %w", err)
	}
	if err := json.Unmarshal(cityRaw, &w.Cities); err != nil {
		return nil, fmt.Errorf("mapdata: parse cities: %w", err)
	}

	return w, nil
}

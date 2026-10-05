// Package mapview renders the offline vector basemap and the trace overlay with
// Qt's native QPainter. It never contacts the network and owns its own pan/zoom
// and hit-testing, so it stays light without a web engine.
package mapview

import (
	"fmt"
	"math"

	qt "github.com/mappu/miqt/qt6"
	"traceroute/internal/mapdata"
)

// Theme holds the palette for the basemap. Colours are "#rrggbb" strings so the
// shell can swap themes without rebuilding the geometry.
type Theme struct {
	Sea       string
	Land      string
	Coast     string
	Border    string
	CityDot   string
	CityLabel string
	HopFill   string
	HUD       string
}

// DarkTheme mirrors the previous dark palette.
func DarkTheme() Theme {
	return Theme{
		Sea:       "#1b2636",
		Land:      "#182630",
		Coast:     "#3a5a73",
		Border:    "#243b4d",
		CityDot:   "#7d9bb0",
		CityLabel: "#9db4c8",
		HopFill:   "#0a2833",
		HUD:       "#c3d0dc",
	}
}

// LightTheme mirrors the previous light palette.
func LightTheme() Theme {
	return Theme{
		Sea:       "#dfe8f1",
		Land:      "#f5f8fb",
		Coast:     "#9db4c8",
		Border:    "#c3d0dc",
		CityDot:   "#8fa6b8",
		CityLabel: "#6f8698",
		HopFill:   "#d8e4ee",
		HUD:       "#3a4a5a",
	}
}

// Marker is one drawn point (a hop, a correlated hop or a synthetic target).
type Marker struct {
	X, Y    float64 // normalized Mercator
	Radius  float64 // screen pixels
	Color   string
	Fill    bool
	Ring    bool
	Label   string // small permanent label drawn to the right
	Tooltip string
	ID      string
	Meta    any
}

// Route is one trace path as normalized Mercator points.
type Route struct {
	Color  string
	Points [][2]float64
}

// Origin is a confirmed/likely origin marker.
type Origin struct {
	X, Y    float64
	Label   string
	Tooltip string
	ID      string
	Meta    any
}

// LegendEntry is one colour key drawn in the map's TRACES legend overlay.
type LegendEntry struct {
	Color string
	Label string
}

// Model is everything the overlay draws, in normalized Mercator coordinates.
type Model struct {
	Routes  []Route
	Markers []Marker
	Origins []Origin
	Legend  []LegendEntry
	HUD     string
}

type hit struct {
	x, y, r float64
	id      string
	meta    any
}

// MapView is the custom-painted map widget.
type MapView struct {
	*qt.QWidget
	world    *mapdata.World
	theme    Theme
	landPath *qt.QPainterPath
	borders  *qt.QPainterPath

	model Model

	zoom             float64
	centerX, centerY float64

	dragging     bool
	dragX, dragY int
	moved        bool

	hits []hit

	onSelect  func(id string, meta any, gx, gy int)
	onContext func(id string, meta any, gx, gy int)

	fitOnce bool

	motion      bool
	phase       float64
	motionTimer *qt.QTimer
}

// New builds the map widget from a loaded world.
func New(world *mapdata.World) *MapView {
	m := &MapView{
		QWidget: qt.NewQWidget2(),
		world:   world,
		theme:   DarkTheme(),
		zoom:    2,
	}
	m.centerX, m.centerY = mapdata.Mercator(25, 10)
	m.SetMinimumSize2(240, 200)
	m.QWidget.SetMouseTracking(true)

	m.landPath = buildPath(world.Land)
	m.borders = buildPath(flatten(world.Countries))

	m.OnPaintEvent(func(super func(*qt.QPaintEvent), e *qt.QPaintEvent) { m.paint() })
	m.OnResizeEvent(func(super func(*qt.QResizeEvent), e *qt.QResizeEvent) { m.Update() })
	m.OnWheelEvent(func(super func(*qt.QWheelEvent), e *qt.QWheelEvent) { m.wheel(e) })
	m.OnMousePressEvent(func(super func(*qt.QMouseEvent), e *qt.QMouseEvent) { m.press(e) })
	m.OnMouseMoveEvent(func(super func(*qt.QMouseEvent), e *qt.QMouseEvent) { m.move(e) })
	m.OnMouseReleaseEvent(func(super func(*qt.QMouseEvent), e *qt.QMouseEvent) { m.release(e) })
	m.OnContextMenuEvent(func(super func(*qt.QContextMenuEvent), e *qt.QContextMenuEvent) { m.context(e) })

	// Route-motion ticker: advances a phase used to place a travelling marker
	// along each route. Off by default.
	m.motionTimer = qt.NewQTimer2(m.QObject)
	m.motionTimer.SetInterval(50)
	m.motionTimer.OnTimeout(func() {
		m.phase = math.Mod(m.phase+0.01, 1)
		m.Update()
	})

	return m
}

// SetTheme swaps the palette.
func (m *MapView) SetTheme(t Theme) {
	m.theme = t
	m.Update()
}

// SetMotion turns the travelling route-marker animation on or off.
func (m *MapView) SetMotion(on bool) {
	m.motion = on
	if m.motionTimer != nil {
		if on {
			m.motionTimer.Start(50)
		} else {
			m.motionTimer.Stop()
		}
	}
	m.Update()
}

// SetModel replaces the overlay and repaints.
func (m *MapView) SetModel(model Model) {
	m.model = model
	if !m.fitOnce && len(model.Markers) > 0 {
		m.FitModel()
		m.fitOnce = true
	}
	m.Update()
}

// OnSelect installs the marker click handler; gx/gy are global pixels.
func (m *MapView) OnSelect(fn func(id string, meta any, gx, gy int)) { m.onSelect = fn }

// OnContext installs the marker right-click handler; gx/gy are global pixels.
func (m *MapView) OnContext(fn func(id string, meta any, gx, gy int)) { m.onContext = fn }

// ---- geometry helpers ----

func flatten(countries []mapdata.Country) []mapdata.Polygon {
	var out []mapdata.Polygon
	for _, c := range countries {
		out = append(out, c.Polygons...)
	}
	return out
}

func buildPath(polys []mapdata.Polygon) *qt.QPainterPath {
	p := qt.NewQPainterPath()
	for _, poly := range polys {
		for _, ring := range poly.Rings {
			if len(ring) == 0 {
				continue
			}
			for i, pt := range ring {
				x, y := mapdata.Mercator(pt.Lat, pt.Lon)
				q := qt.NewQPointF3(x, y)
				if i == 0 {
					p.MoveTo(q)
				} else {
					p.LineTo(q)
				}
			}
			p.CloseSubpath()
		}
	}
	return p
}

func (m *MapView) scale() float64 {
	return mapdata.TileSize * math.Pow(2, m.zoom)
}

// screen maps a normalized Mercator point to widget pixels.
func (m *MapView) screen(nx, ny float64, w, h float64) (float64, float64) {
	k := m.scale()
	return (nx-m.centerX)*k + w/2, (ny-m.centerY)*k + h/2
}

// unproject maps widget pixels to a normalized Mercator point.
func (m *MapView) unproject(x, y, w, h float64) (float64, float64) {
	k := m.scale()
	return m.centerX + (x-w/2)/k, m.centerY + (y-h/2)/k
}

// FitModel zooms so every marker is visible.
func (m *MapView) FitModel() {
	if len(m.model.Markers) == 0 {
		return
	}
	minX, minY := math.Inf(1), math.Inf(1)
	maxX, maxY := math.Inf(-1), math.Inf(-1)
	include := func(x, y float64) {
		minX, minY = math.Min(minX, x), math.Min(minY, y)
		maxX, maxY = math.Max(maxX, x), math.Max(maxY, y)
	}
	for _, mk := range m.model.Markers {
		include(mk.X, mk.Y)
	}
	for _, o := range m.model.Origins {
		include(o.X, o.Y)
	}
	w := float64(maxInt(m.Width(), 1))
	h := float64(maxInt(m.Height(), 1))
	spanX := math.Max(maxX-minX, 1e-6)
	spanY := math.Max(maxY-minY, 1e-6)
	k := math.Min(w*0.8/spanX, h*0.8/spanY)
	z := math.Log2(k / mapdata.TileSize)
	m.zoom = clamp(z, 1, mapdata.MaxZoom)
	m.centerX = (minX + maxX) / 2
	m.centerY = (minY + maxY) / 2
}

// Focus centers on a normalized Mercator point.
func (m *MapView) Focus(x, y float64) {
	m.centerX, m.centerY = x, y
	if m.zoom < 4 {
		m.zoom = 4
	}
	m.Update()
}

// ---- painting ----

var colorCache = map[string]*qt.QColor{}

func col(hex string) *qt.QColor {
	if c, ok := colorCache[hex]; ok {
		return c
	}
	c := qt.NewQColor6(hex)
	colorCache[hex] = c
	return c
}

func (m *MapView) paint() {
	p := qt.NewQPainter2(m.QPaintDevice)
	defer p.Delete()
	p.SetRenderHint(qt.QPainter__Antialiasing)

	w := float64(m.Width())
	h := float64(m.Height())

	p.SetBrush(qt.NewQBrush3(col(m.theme.Sea)))
	p.SetPenWithStyle(qt.NoPen)
	p.DrawRect2(0, 0, int(w), int(h))

	k := m.scale()

	// Basemap and routes share the scene transform.
	p.Save()
	p.Translate(qt.NewQPointF3(w/2, h/2))
	p.Scale(k, k)
	p.Translate(qt.NewQPointF3(-m.centerX, -m.centerY))

	p.FillPath(m.landPath, qt.NewQBrush3(col(m.theme.Land)))
	coast := qt.NewQPen3(col(m.theme.Coast))
	coast.SetCosmetic(true)
	coast.SetWidthF(0.8)
	p.SetPenWithPen(coast)
	p.SetBrush(qt.NewQBrush2(qt.NoBrush))
	p.DrawPath(m.landPath)

	border := qt.NewQPen3(col(m.theme.Border))
	border.SetCosmetic(true)
	border.SetWidthF(0.5)
	p.SetPenWithPen(border)
	p.DrawPath(m.borders)

	for _, r := range m.model.Routes {
		if len(r.Points) < 2 {
			continue
		}
		path := pathFromPoints(r.Points)
		glow := qt.NewQPen3(col(r.Color))
		glow.SetCosmetic(true)
		glow.SetWidthF(6)
		glow.SetCapStyle(qt.RoundCap)
		p.SetPenWithPen(glow)
		p.SetOpacity(0.35)
		p.DrawPath(path)

		line := qt.NewQPen3(col(r.Color))
		line.SetCosmetic(true)
		line.SetWidthF(1.8)
		line.SetCapStyle(qt.RoundCap)
		p.SetPenWithPen(line)
		p.SetOpacity(0.95)
		p.DrawPath(path)
		path.Delete()
	}
	p.SetOpacity(1)
	p.Restore()

	// Overlay: markers, city labels, origins, HUD (screen space).
	m.hits = m.hits[:0]
	m.drawCities(p)
	for _, mk := range m.model.Markers {
		m.drawMarker(p, mk, w, h)
	}
	for _, o := range m.model.Origins {
		m.drawOrigin(p, o, w, h)
	}
	if m.motion {
		m.drawMotion(p, w, h)
	}
	m.drawLegend(p)
	m.drawScaleBar(p)
	m.drawHUD(p)
}

func pathFromPoints(points [][2]float64) *qt.QPainterPath {
	p := qt.NewQPainterPath()
	p.MoveTo(qt.NewQPointF3(points[0][0], points[0][1]))
	for _, pt := range points[1:] {
		p.LineTo(qt.NewQPointF3(pt[0], pt[1]))
	}
	return p
}

func (m *MapView) drawCities(p *qt.QPainter) {
	w := float64(m.Width())
	h := float64(m.Height())
	showMajor := m.zoom >= 3
	showAll := m.zoom >= 5
	dot := qt.NewQBrush3(col(m.theme.CityDot))
	p.SetBrush(dot)
	p.SetPenWithStyle(qt.NoPen)
	font := qt.NewQFont()
	font.SetPointSize(7)
	p.SetFont(font)
	for _, c := range m.world.Cities {
		nx, ny := mapdata.Mercator(c.Lat, c.Lon)
		x, y := m.screen(nx, ny, w, h)
		if x < -20 || y < -20 || x > w+20 || y > h+20 {
			continue
		}
		p.DrawEllipse2(int(x-1), int(y-1), 2, 2)
		if showAll || (showMajor && (c.WorldCity || c.Pop >= 2_000_000)) {
			p.SetPenWithPen(qt.NewQPen3(col(m.theme.CityLabel)))
			p.DrawText(qt.NewQPointF3(x+3, y+3), c.Name)
			p.SetPenWithStyle(qt.NoPen)
			p.SetBrush(dot)
		}
	}
}

func (m *MapView) drawMarker(p *qt.QPainter, mk Marker, w, h float64) {
	x, y := m.screen(mk.X, mk.Y, w, h)
	color := col(mk.Color)
	pen := qt.NewQPen3(color)
	pen.SetWidthF(2)
	if mk.Ring {
		pen.SetWidthF(2.6)
	}
	p.SetPenWithPen(pen)
	if mk.Fill {
		p.SetBrush(qt.NewQBrush3(color))
	} else {
		p.SetBrush(qt.NewQBrush3(col(m.theme.HopFill)))
	}
	p.DrawEllipse3(qt.NewQPointF3(x, y), mk.Radius, mk.Radius)
	if mk.Label != "" {
		font := qt.NewQFont()
		font.SetPointSize(7)
		p.SetFont(font)
		p.SetPenWithPen(qt.NewQPen3(color))
		p.DrawText(qt.NewQPointF3(x+mk.Radius+2, y+3), mk.Label)
	}
	m.hits = append(m.hits, hit{x: x, y: y, r: math.Max(mk.Radius, 6), id: mk.ID, meta: mk.Meta})
}

func (m *MapView) drawOrigin(p *qt.QPainter, o Origin, w, h float64) {
	x, y := m.screen(o.X, o.Y, w, h)
	color := col("#f5b642")
	p.SetBrush(qt.NewQBrush3(color))
	p.SetPenWithPen(qt.NewQPen3(col("#3a2a00")))
	// Small diamond so it reads differently from hop circles.
	path := qt.NewQPainterPath()
	path.MoveTo(qt.NewQPointF3(x, y-8))
	path.LineTo(qt.NewQPointF3(x+8, y))
	path.LineTo(qt.NewQPointF3(x, y+8))
	path.LineTo(qt.NewQPointF3(x-8, y))
	path.CloseSubpath()
	p.FillPath(path, qt.NewQBrush3(color))
	p.DrawPath(path)
	path.Delete()
	m.hits = append(m.hits, hit{x: x, y: y, r: 9, id: o.ID, meta: o.Meta})
}

func (m *MapView) drawHUD(p *qt.QPainter) {
	if m.model.HUD == "" {
		return
	}
	p.SetPenWithPen(qt.NewQPen3(col(m.theme.HUD)))
	font := qt.NewQFont()
	font.SetPointSize(9)
	font.SetBold(true)
	p.SetFont(font)
	p.DrawText(qt.NewQPointF3(10, float64(m.Height())-12), m.model.HUD)
}

// drawMotion paints a travelling marker along each route, offset per route so
// the paths do not pulse in lock-step.
func (m *MapView) drawMotion(p *qt.QPainter, w, h float64) {
	for i, r := range m.model.Routes {
		if len(r.Points) < 2 {
			continue
		}
		frac := math.Mod(m.phase+float64(i)*0.17, 1)
		idx := int(frac * float64(len(r.Points)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(r.Points) {
			idx = len(r.Points) - 1
		}
		x, y := m.screen(r.Points[idx][0], r.Points[idx][1], w, h)
		if x < -50 || y < -50 || x > w+50 || y > h+50 {
			continue
		}
		p.SetPenWithStyle(qt.NoPen)
		p.SetBrush(qt.NewQBrush3(col(r.Color)))
		p.SetOpacity(0.3)
		p.DrawEllipse3(qt.NewQPointF3(x, y), 8, 8)
		p.SetOpacity(1)
		p.DrawEllipse3(qt.NewQPointF3(x, y), 3.5, 3.5)
	}
}

// drawLegend paints the TRACES key in the top-right corner: one coloured dot
// and label per visible trace. It is a no-op when no legend entries exist.
func (m *MapView) drawLegend(p *qt.QPainter) {
	if len(m.model.Legend) == 0 {
		return
	}
	font := qt.NewQFont()
	font.SetPointSize(8)
	p.SetFont(font)
	fm := qt.NewQFontMetrics(font)

	width := 0
	for _, e := range m.model.Legend {
		if w := fm.HorizontalAdvance(e.Label) + 24; w > width {
			width = w
		}
	}
	const pad = 8
	rowH := fm.Height() + 2
	boxW := float64(width + pad*2)
	boxH := float64(len(m.model.Legend)*rowH + pad*2)
	x := float64(m.Width()) - boxW - 10
	y := 10.0
	if x < 10 {
		return
	}

	p.SetPenWithStyle(qt.NoPen)
	p.SetBrush(qt.NewQBrush3(col("#0b1119")))
	p.SetOpacity(0.45)
	p.DrawRoundedRect(qt.NewQRectF4(x, y, boxW, boxH), 6, 6)
	p.SetOpacity(1)

	textPen := qt.NewQPen3(col(m.theme.HUD))
	ty := y + pad
	for _, e := range m.model.Legend {
		p.SetBrush(qt.NewQBrush3(col(e.Color)))
		p.SetPenWithStyle(qt.NoPen)
		p.DrawEllipse3(qt.NewQPointF3(x+pad+5, ty+float64(rowH)/2), 4, 4)
		p.SetPenWithPen(textPen)
		p.DrawText(qt.NewQPointF3(x+pad+15, ty+float64(fm.Ascent())+2), e.Label)
		ty += float64(rowH)
	}
}

// drawScaleBar paints an approximate distance scale at the map centre latitude.
func (m *MapView) drawScaleBar(p *qt.QPainter) {
	w := float64(m.Width())
	h := float64(m.Height())
	centerLat := mercatorLat(m.centerY)
	mpp := m.metersPerPixel(centerLat)
	if mpp <= 0 || math.IsInf(mpp, 0) || math.IsNaN(mpp) {
		return
	}
	nice := niceDistance(mpp * 110)
	if nice <= 0 {
		return
	}
	px := nice / mpp
	if px < 28 || px > w-40 {
		return
	}
	x2 := w - 20
	x1 := x2 - px
	y := h - 22

	p.SetPenWithPen(qt.NewQPen3(col(m.theme.HUD)))
	p.DrawLine2(int(x1), int(y), int(x2), int(y))
	p.DrawLine2(int(x1), int(y-4), int(x1), int(y+4))
	p.DrawLine2(int(x2), int(y-4), int(x2), int(y+4))

	font := qt.NewQFont()
	font.SetPointSize(8)
	p.SetFont(font)
	label := formatDistance(nice)
	fm := qt.NewQFontMetrics(font)
	p.DrawText(qt.NewQPointF3((x1+x2)/2-float64(fm.HorizontalAdvance(label))/2, y-7), label)
}

// mercatorLat inverts the Web-Mercator y back to degrees latitude.
func mercatorLat(ny float64) float64 {
	n := math.Pi * (1 - 2*ny)
	return math.Atan(math.Sinh(n)) * 180 / math.Pi
}

// metersPerPixel estimates the ground distance covered by one screen pixel at
// the given latitude, for the current zoom.
func (m *MapView) metersPerPixel(lat float64) float64 {
	const earthRadius = 6378137.0
	k := m.scale() // pixels across the full world width
	return (2 * math.Pi * earthRadius * math.Cos(lat*math.Pi/180)) / k
}

// niceDistance rounds a distance up to the next 1/2/5×10ⁿ value, the classic
// choice for a scale bar.
func niceDistance(meters float64) float64 {
	if meters <= 0 {
		return 0
	}
	mag := math.Pow(10, math.Floor(math.Log10(meters)))
	for _, mult := range []float64{1, 2, 5, 10} {
		if mult*mag >= meters {
			return mult * mag
		}
	}
	return 10 * mag
}

// formatDistance renders a scale-bar distance as metres or kilometres.
func formatDistance(meters float64) string {
	if meters >= 1000 {
		km := meters / 1000
		if km == math.Trunc(km) {
			return fmt.Sprintf("%.0f km", km)
		}
		return fmt.Sprintf("%.1f km", km)
	}
	return fmt.Sprintf("%.0f m", meters)
}

// ---- interaction ----

func (m *MapView) hitTest(x, y float64) (string, any, bool) {
	for i := len(m.hits) - 1; i >= 0; i-- {
		hr := m.hits[i]
		dx, dy := x-hr.x, y-hr.y
		if dx*dx+dy*dy <= hr.r*hr.r {
			return hr.id, hr.meta, true
		}
	}
	return "", nil, false
}

func (m *MapView) wheel(e *qt.QWheelEvent) {
	delta := e.AngleDelta()
	dy := float64(delta.Y())
	if dy == 0 {
		return
	}
	w := float64(m.Width())
	h := float64(m.Height())
	pos := e.Position()
	px, py := pos.X(), pos.Y()
	wx, wy := m.unproject(px, py, w, h)
	m.zoom = clamp(m.zoom+dy/480.0, 0, mapdata.MaxZoom)
	m.centerX = wx - (px-w/2)/m.scale()
	m.centerY = wy - (py-h/2)/m.scale()
	m.Update()
}

func (m *MapView) press(e *qt.QMouseEvent) {
	btn := e.QSinglePointEvent.Button()
	pos := e.Position()
	if btn == qt.LeftButton {
		if id, meta, ok := m.hitTest(pos.X(), pos.Y()); ok {
			if m.onSelect != nil {
				gp := m.MapToGlobal(qt.NewQPointF3(pos.X(), pos.Y()))
				m.onSelect(id, meta, int(gp.X()), int(gp.Y()))
			}
			return
		}
	}
	if btn == qt.LeftButton || btn == qt.MiddleButton {
		m.dragging = true
		m.moved = false
		m.dragX, m.dragY = int(pos.X()), int(pos.Y())
		m.SetCursor(qt.NewQCursor2(qt.ClosedHandCursor))
	}
}

func (m *MapView) move(e *qt.QMouseEvent) {
	pos := e.Position()
	if m.dragging {
		dx := int(pos.X()) - m.dragX
		dy := int(pos.Y()) - m.dragY
		if dx != 0 || dy != 0 {
			m.moved = true
		}
		k := m.scale()
		m.centerX -= float64(dx) / k
		m.centerY -= float64(dy) / k
		m.dragX, m.dragY = int(pos.X()), int(pos.Y())
		m.Update()
		return
	}
	if _, _, ok := m.hitTest(pos.X(), pos.Y()); ok {
		m.SetCursor(qt.NewQCursor2(qt.PointingHandCursor))
	} else {
		m.SetCursor(qt.NewQCursor2(qt.ArrowCursor))
	}
}

func (m *MapView) release(e *qt.QMouseEvent) {
	if m.dragging {
		m.dragging = false
		m.SetCursor(qt.NewQCursor2(qt.ArrowCursor))
	}
}

func (m *MapView) context(e *qt.QContextMenuEvent) {
	pos := e.Pos()
	id, meta, ok := m.hitTest(float64(pos.X()), float64(pos.Y()))
	if !ok {
		return
	}
	gp := e.GlobalPos()
	if m.onContext != nil {
		m.onContext(id, meta, gp.X(), gp.Y())
	}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

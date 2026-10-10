package main

import (
	"fmt"
	"time"

	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"

	"traceroute/internal/geolocator"
	"traceroute/internal/history"
)

// saveHistory snapshots the current traces into the history database.
func (u *uiApp) saveHistory() {
	if len(u.traces) == 0 {
		u.status.ShowMessage("nothing to add to history")
		return
	}
	kind := "trace"
	if len(u.traces) > 1 {
		kind = "scan"
	}
	label := u.traces[0].Label
	if len(u.lastTarget) > 0 {
		label = u.lastTarget[0]
	}
	maxHops := u.lastMaxHops
	if maxHops <= 0 {
		maxHops = 30
	}
	req := HistorySaveRequest{Kind: kind, Label: label, MaxHops: maxHops}
	for _, t := range u.traces {
		ht := history.Trace{Label: t.Label, Kind: t.Kind, IP: t.IP, TargetIP: t.TargetIP, Error: t.Error}
		if t.TargetGeo != nil {
			ht.TargetGeo = geoToHistory(t.TargetGeo)
		}
		for _, h := range t.Hops {
			hh := history.Hop{Hop: h.Hop, IP: h.IP, RTTMs: h.RTTMs, IsTarget: h.IsTarget}
			if h.Geo != nil {
				hh.Geo = geoToHistory(h.Geo)
			}
			ht.Hops = append(ht.Hops, hh)
		}
		req.Traces = append(req.Traces, ht)
	}
	if _, err := u.app.SaveHistory(req); err != nil {
		u.status.ShowMessage("could not add to history: " + err.Error())
		return
	}
	u.status.ShowMessage("added results to history")
}

func geoToHistory(g *geolocator.GeoData) *history.Geo {
	return &history.Geo{Lat: g.Lat, Lon: g.Lon, City: g.City, Country: g.Country, ASN: g.ASN, Resolved: g.Resolved}
}

func geoFromHistory(g *history.Geo) geolocator.GeoData {
	return geolocator.GeoData{Lat: g.Lat, Lon: g.Lon, City: g.City, Country: g.Country, ASN: g.ASN, Resolved: g.Resolved}
}

// historyDialog lists saved entries and loads a selection back onto the map.
type historyDialog struct {
	u    *uiApp
	win  *qt.QDialog
	tree *qt.QTreeWidget
}

func (u *uiApp) openHistoryDialog() {
	d := &historyDialog{u: u}
	d.win = newFloatingDialog(u.win.QWidget)
	d.win.SetWindowTitle("History")
	d.win.Resize(720, 520)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	d.tree = qt.NewQTreeWidget2()
	d.tree.SetColumnCount(6)
	d.tree.SetHeaderLabels([]string{"ID", "Kind", "Label", "Created", "Traces", "Hops"})
	d.tree.SetSelectionMode(qt.QAbstractItemView__ExtendedSelection)
	d.tree.OnItemDoubleClicked(func(item *qt.QTreeWidgetItem, col int) { d.load() })
	v.AddWidget2(d.tree.QWidget, 1)

	hint := qt.NewQLabel3("Select one or more entries — Load replays them, Correlate merges their hops on the map.")
	hint.SetWordWrap(true)
	v.AddWidget(hint.QWidget)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	h.AddWidget(newButton("Load selected", func() { d.load() }).QWidget)
	h.AddWidget(newButton("Correlate selected", func() { d.loadCorrelate() }).QWidget)
	h.AddWidget(newButton("Delete", func() { d.remove() }).QWidget)
	h.AddWidget(newButton("Clear all", func() { d.clear() }).QWidget)
	h.AddStretch()
	h.AddWidget(newButton("Refresh", func() { d.refresh() }).QWidget)
	v.AddWidget(row)

	u.historyDlg = d
	d.refresh()
	d.win.Show()
	d.win.Raise()
}

func (d *historyDialog) refresh() {
	d.tree.Clear()
	entries, err := d.u.app.ListHistory()
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	for _, e := range entries {
		item := qt.NewQTreeWidgetItem3(d.tree)
		item.SetText(0, fmt.Sprintf("%d", e.ID))
		item.SetText(1, e.Kind)
		item.SetText(2, e.Label)
		item.SetText(3, time.UnixMilli(e.CreatedAt).Format("2006-01-02 15:04"))
		item.SetText(4, fmt.Sprintf("%d", e.TraceCount))
		item.SetText(5, fmt.Sprintf("%d", e.HopCount))
	}
}

func (d *historyDialog) selectedIDs() []int64 {
	items := d.tree.SelectedItems()
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		var id int64
		fmt.Sscanf(item.Text(0), "%d", &id)
		if id != 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

func (d *historyDialog) load() { d.loadAs(false) }

func (d *historyDialog) loadCorrelate() { d.loadAs(true) }

func (d *historyDialog) loadAs(correlate bool) {
	ids := d.selectedIDs()
	if len(ids) == 0 {
		d.u.status.ShowMessage("select one or more history entries first")
		return
	}
	go func() {
		entries, err := d.u.app.LoadHistory(ids)
		mainthread.Start(func() {
			if err != nil {
				d.u.status.ShowMessage(err.Error())
				return
			}
			d.u.applyHistory(entries, correlate)
			d.win.Close()
		})
	}()
}

func (d *historyDialog) remove() {
	for _, id := range d.selectedIDs() {
		if err := d.u.app.DeleteHistory(id); err != nil {
			d.u.status.ShowMessage(err.Error())
			return
		}
	}
	d.refresh()
}

func (d *historyDialog) clear() {
	if err := d.u.app.ClearHistory(); err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	d.refresh()
}

// applyHistory replaces the live traces with the loaded entry's paths.
func (u *uiApp) applyHistory(entries []history.Entry, correlate bool) {
	var loaded []*traceState
	for _, e := range entries {
		for _, t := range e.Traces {
			idx := len(loaded)
			tr := &traceState{
				ID: idx, Label: t.Label, Kind: t.Kind, IP: t.IP,
				Color: traceColor(idx), TargetIP: t.TargetIP, Error: t.Error, Done: true,
			}
			if t.TargetGeo != nil {
				g := geoFromHistory(t.TargetGeo)
				tr.TargetGeo = &g
			}
			for _, h := range t.Hops {
				hd := hopData{Hop: h.Hop, IP: h.IP, RTTMs: h.RTTMs, HasRTT: h.RTTMs > 0, IsTarget: h.IsTarget}
				if h.Geo != nil {
					g := geoFromHistory(h.Geo)
					hd.Geo = &g
				}
				tr.Hops = append(tr.Hops, hd)
			}
			loaded = append(loaded, tr)
		}
	}
	if len(loaded) == 0 {
		u.status.ShowMessage("nothing to display")
		return
	}
	u.traces = loaded
	u.hidden = map[int]bool{}
	u.focused = loaded[0].ID
	u.selectedHop = -1
	u.sharedHops = map[string]int{}
	u.records = nil
	u.subs = nil
	u.recomputeShared()
	u.setCorrelate(correlate)
	u.status.ShowMessage(fmt.Sprintf("loaded %d path(s)", len(loaded)))
}

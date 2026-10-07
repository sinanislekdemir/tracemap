package main

import (
	"fmt"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"
)

// logWindow is a read-only console pane for one channel. When shown it is
// attached to the main window as a QDockWidget, so it stays docked and can
// never be lost behind the main window (the Wayland-safe replacement for the
// old always-on-top floating windows).
type logWindow struct {
	dock   *qt.QDockWidget
	view   *qt.QPlainTextEdit
	lines  int
	docked bool
}

// newLogWindow builds the channel's dock and text view without adding either to
// the main window. Docking happens on first show, so a channel that only
// receives log lines never claims screen space until the user opens it.
func newLogWindow(title string) *logWindow {
	dock := qt.NewQDockWidget2(title)
	view := qt.NewQPlainTextEdit2()
	view.SetReadOnly(true)
	view.SetMaximumBlockCount(2000)
	view.SetFont(monoFont())
	view.SetMinimumHeight(140)
	dock.SetWidget(view.QWidget)
	return &logWindow{dock: dock, view: view}
}

func (l *logWindow) clear() {
	l.view.Clear()
	l.lines = 0
}

func (l *logWindow) line(level, text string) {
	ts := time.Now().Format("15:04:05")
	l.view.AppendPlainText(fmt.Sprintf("%s  %-5s %s", ts, strings.ToUpper(level), text))
	l.lines++
}

// ensureChannel returns the log window for a channel, creating it on first use.
// It does not dock or show the window; openChannel does that.
func (u *uiApp) ensureChannel(kind string) *logWindow {
	if w, ok := u.channels[kind]; ok {
		return w
	}
	w := newLogWindow(kind)
	u.channels[kind] = w
	return w
}

// dockChannel attaches a channel's dock to the bottom of the main window and
// tabifies it beside any channel already shown there, so every channel shares
// one panel. Both docks must be visible for Qt's tabify to take effect, hence
// the show before grouping.
func (u *uiApp) dockChannel(w *logWindow) {
	if w.docked {
		return
	}
	w.docked = true
	u.win.AddDockWidget(qt.BottomDockWidgetArea, w.dock)
	w.dock.Show()
	if anchor := u.visibleChannelAnchor(w); anchor != nil {
		u.win.TabifyDockWidget(anchor, w.dock)
	}
}

// visibleChannelAnchor returns the dock of the first other channel that is
// currently shown, or nil when none is. Tabifying against a hidden dock is a
// no-op in Qt, so the shared panel always grows from a visible tab.
func (u *uiApp) visibleChannelAnchor(exclude *logWindow) *qt.QDockWidget {
	for _, w := range u.channels {
		if w == exclude || !w.docked || !w.dock.IsVisible() {
			continue
		}
		return w.dock
	}
	return nil
}

// openChannel docks (on first use) and shows a channel window.
func (u *uiApp) openChannel(kind string) *logWindow {
	w := u.ensureChannel(kind)
	u.dockChannel(w)
	w.dock.Show()
	w.dock.Raise()
	return w
}

func (u *uiApp) logLine(channel, level, text string) {
	u.ensureChannel(channel).line(level, text)
}

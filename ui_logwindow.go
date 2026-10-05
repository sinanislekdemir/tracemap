package main

import (
	"fmt"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"
)

// logWindow is a floating, read-only terminal window for one channel.
type logWindow struct {
	win   *qt.QWidget
	view  *qt.QPlainTextEdit
	lines int
}

func newLogWindow(title string) *logWindow {
	win := qt.NewQWidget2()
	win.SetWindowTitle("traceroute · " + title)
	win.Resize(640, 340)
	keepOnTop(win)
	v := qt.NewQVBoxLayout(win)
	view := qt.NewQPlainTextEdit2()
	view.SetReadOnly(true)
	view.SetMaximumBlockCount(2000)
	view.SetFont(monoFont())
	v.AddWidget(view.QWidget)
	return &logWindow{win: win, view: view}
}

func (l *logWindow) show() {
	l.win.Show()
	l.win.Raise()
	l.win.ActivateWindow()
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

// ensureChannel returns the log window for a channel, creating and showing it
// on first use.
func (u *uiApp) ensureChannel(kind string) *logWindow {
	if w, ok := u.channels[kind]; ok {
		return w
	}
	w := newLogWindow(kind)
	u.channels[kind] = w
	return w
}

// openChannel creates and shows a channel window.
func (u *uiApp) openChannel(kind string) *logWindow {
	w := u.ensureChannel(kind)
	w.show()
	return w
}

func (u *uiApp) logLine(channel, level, text string) {
	u.ensureChannel(channel).line(level, text)
}

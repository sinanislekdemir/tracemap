package main

import (
	"sync"

	qt "github.com/mappu/miqt/qt6"
)

var (
	monoOnce sync.Once
	monoVal  *qt.QFont
)

// monoFont returns a fixed-pitch "techy" monospace font, preferring common
// developer fonts and falling back to whatever fixed-pitch family the system
// provides. It is resolved once.
func monoFont() *qt.QFont {
	monoOnce.Do(func() {
		available := map[string]bool{}
		for _, f := range qt.QFontDatabase_Families() {
			available[f] = true
		}
		preferred := []string{
			"JetBrains Mono", "JetBrainsMono Nerd Font", "Fira Code", "Cascadia Code",
			"Source Code Pro", "IBM Plex Mono", "Hack", "Ubuntu Mono", "Iosevka",
			"Noto Sans Mono", "DejaVu Sans Mono", "Liberation Mono",
		}
		family := "monospace"
		for _, f := range preferred {
			if available[f] {
				family = f
				break
			}
		}
		f := qt.NewQFont2(family)
		f.SetPointSize(10)
		f.SetFixedPitch(true)
		f.SetStyleHint(qt.QFont__Monospace)
		monoVal = f
	})
	return monoVal
}

// terminalStyle paints a console-like pane as an old phosphor terminal: a black
// background with lime-green text and a green selection highlight.
const terminalStyle = "QPlainTextEdit {" +
	"background-color: #000000;" +
	"color: #33ff33;" +
	"selection-background-color: #123f12;" +
	"selection-color: #d8ffd8;" +
	"}"

// applyTerminalStyle gives a plain-text pane the shared terminal look: the
// monospace "techy" font plus the black/lime palette. Every console-like pane
// calls this so the logs, netcat sessions and tool logs read alike.
func applyTerminalStyle(view *qt.QPlainTextEdit) {
	view.SetFont(monoFont())
	view.SetStyleSheet(terminalStyle)
}

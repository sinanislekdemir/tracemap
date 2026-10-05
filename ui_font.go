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

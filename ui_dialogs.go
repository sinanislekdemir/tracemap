package main

import (
	"strings"

	qt "github.com/mappu/miqt/qt6"
)

// qtDialogs implements the backend Dialogs interface with native Qt dialogs.
type qtDialogs struct {
	parent *qt.QWidget
}

func (d qtDialogs) filterString(filters []FileFilter) string {
	var parts []string
	for _, f := range filters {
		var globs []string
		for _, p := range strings.Split(f.Pattern, ";") {
			p = strings.TrimSpace(p)
			if p != "" {
				globs = append(globs, p)
			}
		}
		if len(globs) == 0 {
			continue
		}
		parts = append(parts, f.DisplayName+" ("+strings.Join(globs, " ")+")")
	}
	return strings.Join(parts, ";;")
}

func (d qtDialogs) OpenFile(title string, filters []FileFilter) (string, error) {
	return qt.QFileDialog_GetOpenFileName4(d.parent, title, "", d.filterString(filters)), nil
}

func (d qtDialogs) SaveFile(title, defaultName string, filters []FileFilter) (string, error) {
	return qt.QFileDialog_GetSaveFileName4(d.parent, title, defaultName, d.filterString(filters)), nil
}

func (d qtDialogs) Confirm(title, message string) bool {
	res := qt.QMessageBox_Question2(d.parent, title, message, qt.QMessageBox__Yes, qt.QMessageBox__No)
	return res == int(qt.QMessageBox__Yes)
}

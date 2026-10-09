package main

import (
	"embed"

	qt "github.com/mappu/miqt/qt6"
)

// The release ships these files next to the binary (and, for the .deb/.rpm/
// AppImage, under /usr/share/doc/tracemap), but embedding them keeps the About
// window self-contained and works offline. The Go build refuses to compile if a
// file is missing, so the notices can never silently drop out of a build.
//
//go:embed LICENSE THIRD_PARTY_NOTICES.md LICENSES/LGPL-3.0.txt LICENSES/GPL-3.0.txt
var noticeFiles embed.FS

// noticeDocs are the embedded documents shown by the notices viewer, in menu
// order. Markdown documents are rendered; plain-text licenses stay monospaced.
var noticeDocs = []struct {
	title    string
	path     string
	markdown bool
}{
	{"Third-party notices", "THIRD_PARTY_NOTICES.md", true},
	{"MIT License", "LICENSE", false},
	{"GNU LGPL v3", "LICENSES/LGPL-3.0.txt", false},
	{"GNU GPL v3", "LICENSES/GPL-3.0.txt", false},
}

// noticesDialog is a read-only viewer for the license and third-party notice
// texts; the combo box switches between the embedded documents.
type noticesDialog struct {
	win      *qt.QDialog
	combo    *qt.QComboBox
	view     *qt.QTextBrowser
	baseFont *qt.QFont
}

// showDoc renders the i-th document: Markdown with GitHub extensions (tables,
// autolinks) or, for the plain-text licenses, fixed-pitch text.
func (d *noticesDialog) showDoc(i int) {
	if i < 0 || i >= len(noticeDocs) {
		return
	}
	doc := noticeDocs[i]
	data, err := noticeFiles.ReadFile(doc.path)
	if err != nil {
		d.view.SetFont(monoFont())
		d.view.SetPlainText("could not read " + doc.path + ": " + err.Error())
		return
	}
	if doc.markdown {
		d.view.SetFont(d.baseFont)
		d.view.Document().SetMarkdown2(string(data), qt.QTextDocument__MarkdownDialectGitHub)
		return
	}
	d.view.SetFont(monoFont())
	d.view.SetPlainText(string(data))
}

// openNotices shows the embedded license and third-party notices: the MIT
// LICENSE, THIRD_PARTY_NOTICES.md and the full Qt LGPL/GPL texts. Making them
// viewable from inside the app satisfies the "accompany the binary with the
// license" condition even when the notice files are not installed alongside.
func (u *uiApp) openNotices() {
	d := &noticesDialog{}
	d.win = newFloatingDialog(u.win.QWidget)
	d.win.SetWindowTitle("Licenses & third-party notices")
	d.win.Resize(820, 640)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	d.combo = qt.NewQComboBox2()
	titles := make([]string, 0, len(noticeDocs))
	for _, doc := range noticeDocs {
		titles = append(titles, doc.title)
	}
	d.combo.AddItems(titles)
	v.AddWidget(d.combo.QWidget)

	d.view = qt.NewQTextBrowser2()
	d.view.SetOpenExternalLinks(true)
	// Snapshot the widget's default font so the Markdown view can restore it
	// after a plain-text license has switched the viewer to monospace.
	d.baseFont = d.view.Font()
	v.AddWidget2(d.view.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	h.AddStretch()
	h.AddWidget(newButton("Close", func() { d.win.Close() }).QWidget)
	v.AddWidget(row)

	d.combo.OnCurrentIndexChanged(func(i int) { d.showDoc(i) })
	d.showDoc(0)

	d.win.Show()
	d.win.Raise()
}

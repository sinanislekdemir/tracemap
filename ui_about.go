package main

import (
	"fmt"
	"runtime/debug"
	"strings"

	qt "github.com/mappu/miqt/qt6"
)

// Application identity, shared by the About window. The copyright year is the
// year of first publication; widen it to a range if a later year warrants it.
const (
	appName      = "Traceroute Map"
	appAuthor    = "Sinan Islekdemir"
	appEmail     = "sinan@islekdemir.com"
	appCopyright = "© 2026 Sinan Islekdemir"
	appLicense   = "MIT"
)

// aboutBody is the rich-text About blurb. It names the third-party components
// and their licenses because the app links Qt (LGPL) and several permissively
// licensed Go modules.
const aboutBody = `<p style="margin-top:0">A desktop traceroute visualizer. It runs
<code>traceroute</code>/<code>tracert</code> from your machine, geolocates every responsive hop and draws the
path on an offline vector world map &mdash; with DNS discovery, subdomain
enumeration, port scanning, domain analysis and origin unmasking.</p>
<hr/>
<table cellspacing="6">
<tr><td><b>Author</b></td><td>` + appAuthor + `</td></tr>
<tr><td><b>Email</b></td><td><a href="mailto:` + appEmail + `">` + appEmail + `</a></td></tr>
<tr><td><b>Copyright</b></td><td>` + appCopyright + `</td></tr>
<tr><td><b>License</b></td><td>` + appLicense + `</td></tr>
</table>
<hr/>
<p style="margin-bottom:0"><b>Third-party components:</b> Qt&nbsp;6 (LGPL-3.0), MIQT (MIT),
the Go standard library and modules (BSD-3-Clause / MIT / ISC). MaxMind GeoLite2
databases are optional, supplied by the user and covered by MaxMind's End User
License Agreement. The full license texts are available under <b>Licenses &amp;
notices</b>.</p>`

// appVersion reports the build's module version. Local `go build`s report
// "(devel)", so fall back to a short VCS revision when the Go toolchain stamped
// one into the binary.
func appVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v")
		}
		var rev, dirty string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "+dirty"
				}
			}
		}
		if len(rev) >= 7 {
			return "dev (" + rev[:7] + dirty + ")"
		}
	}
	return "dev"
}

// openAbout shows the About window: version, author, license and the
// third-party components the app links. It also offers Qt's own About box,
// which Qt expects applications to expose under the LGPL.
func (u *uiApp) openAbout() {
	d := newFloatingDialog(u.win.QWidget)
	d.SetWindowTitle("About " + appName)
	d.Resize(560, 500)
	v := qt.NewQVBoxLayout(d.QWidget)
	v.SetSpacing(8)

	title := qt.NewQLabel3(fmt.Sprintf("%s  <span style='color:#9db4c8; font-size:small'>%s</span>", appName, appVersion()))
	tf := qt.NewQFont()
	tf.SetPointSize(16)
	tf.SetBold(true)
	title.SetFont(tf)
	title.SetTextFormat(qt.RichText)
	v.AddWidget(title.QWidget)

	body := qt.NewQLabel3(aboutBody)
	body.SetTextFormat(qt.RichText)
	body.SetWordWrap(true)
	body.SetOpenExternalLinks(true)
	body.SetTextInteractionFlags(qt.TextBrowserInteraction)
	v.AddWidget(body.QWidget)
	v.AddStretch()

	note := qt.NewQLabel2()
	note.SetText("")
	v.AddWidget(note.QWidget)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	h.AddWidget(newButton("Copy email", func() {
		qt.QGuiApplication_Clipboard().SetText(appEmail)
		note.SetText("copied " + appEmail)
	}).QWidget)
	h.AddWidget(newButton("About Qt", func() {
		qt.QMessageBox_AboutQt2(d.QWidget, "About Qt")
	}).QWidget)
	h.AddWidget(newButton("Licenses & notices", func() { u.openNotices() }).QWidget)
	h.AddStretch()
	h.AddWidget(newButton("Close", func() { d.Close() }).QWidget)
	v.AddWidget(row)

	d.Show()
	d.Raise()
}

package main

import (
	"fmt"
	"strconv"

	qt "github.com/mappu/miqt/qt6"

	"traceroute/internal/cheatsheets"
)

// cheatsheetForPort picks the protocol sheet matching a well-known port.
func cheatsheetForPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 25, 587, 465:
		return "smtp"
	case 110, 995:
		return "pop3"
	case 80, 443, 8080, 8443:
		return "http"
	case 143, 993:
		return "imap"
	case 53:
		return "dns"
	case 6667, 6697:
		return "irc"
	case 6379:
		return "redis"
	case 3306:
		return "mysql"
	case 43:
		return "whois"
	default:
		return ""
	}
}

type cheatsheetDialog struct {
	win    *qt.QDialog
	combo  *qt.QComboBox
	stack  *qt.QStackedWidget
	status *qt.QLabel
}

// openCheatsheet opens the netcat protocol reference, optionally preselecting a
// sheet id.
func (u *uiApp) openCheatsheet(id string) {
	d := &cheatsheetDialog{}
	d.win = newFloatingDialog(u.win.QWidget)
	d.win.SetWindowTitle("Netcat cheatsheets")
	d.win.Resize(780, 720)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	top := qt.NewQWidget2()
	th := qt.NewQHBoxLayout(top)
	th.SetContentsMargins(0, 0, 0, 0)
	th.AddWidget(qt.NewQLabel3("Protocol").QWidget)
	d.combo = qt.NewQComboBox2()
	th.AddWidget2(d.combo.QWidget, 1)
	v.AddWidget(top)

	d.status = qt.NewQLabel3("")
	d.status.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	v.AddWidget(d.status.QWidget)

	d.stack = qt.NewQStackedWidget2()
	sheets := cheatsheets.All()
	titles := make([]string, 0, len(sheets))
	for i := range sheets {
		titles = append(titles, fmt.Sprintf("%s  ·  %s", sheets[i].Protocol, sheets[i].Port))
		d.stack.AddWidget(buildCheatsheetPage(&sheets[i], d))
	}
	d.combo.AddItems(titles)
	v.AddWidget2(d.stack.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	h.AddStretch()
	h.AddWidget(newButton("Close", func() { d.win.Close() }).QWidget)
	v.AddWidget(row)

	d.combo.OnCurrentIndexChanged(func(idx int) {
		if idx >= 0 {
			d.stack.SetCurrentIndex(idx)
		}
	})
	if id != "" {
		for i := range sheets {
			if sheets[i].ID == id {
				d.combo.SetCurrentIndex(i)
				d.stack.SetCurrentIndex(i)
				break
			}
		}
	}

	d.win.Show()
	d.win.Raise()
}

func buildCheatsheetPage(s *cheatsheets.Sheet, d *cheatsheetDialog) *qt.QWidget {
	content := qt.NewQWidget2()
	v := qt.NewQVBoxLayout(content)
	v.SetContentsMargins(10, 10, 10, 10)
	v.SetSpacing(6)

	head := qt.NewQLabel3(fmt.Sprintf("<b>%s</b>  ·  %s", s.Title, s.Port))
	v.AddWidget(head.QWidget)
	summary := qt.NewQLabel3(s.Summary)
	summary.SetWordWrap(true)
	summary.SetTextInteractionFlags(qt.TextSelectableByMouse)
	v.AddWidget(summary.QWidget)

	for _, g := range s.Groups {
		gl := qt.NewQLabel3("<b>" + g.Name + "</b>")
		v.AddWidget(gl.QWidget)
		for _, c := range g.Commands {
			v.AddWidget(cheatsheetRow(c, d))
		}
	}
	v.AddStretch()

	sa := qt.NewQScrollArea2()
	sa.SetWidgetResizable(true)
	sa.SetWidget(content)
	return sa.QWidget
}

func cheatsheetRow(c cheatsheets.Command, d *cheatsheetDialog) *qt.QWidget {
	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 1, 0, 1)
	h.SetSpacing(8)

	left := qt.NewQWidget2()
	lv := qt.NewQVBoxLayout(left)
	lv.SetContentsMargins(0, 0, 0, 0)
	lv.SetSpacing(0)

	label := qt.NewQLabel3(c.Label)
	lf := qt.NewQFont()
	lf.SetBold(true)
	label.SetFont(lf)
	lv.AddWidget(label.QWidget)

	cmd := c.Command
	if cmd == "" {
		cmd = "↵ blank line"
	}
	code := qt.NewQLabel3(cmd)
	code.SetFont(monoFont())
	code.SetTextInteractionFlags(qt.TextSelectableByMouse)
	lv.AddWidget(code.QWidget)

	if c.Note != "" {
		note := qt.NewQLabel3(c.Note)
		note.SetWordWrap(true)
		lv.AddWidget(note.QWidget)
	}
	h.AddWidget2(left, 1)

	if c.Command != "" {
		val := c.Command
		btn := newButton("Copy", func() {
			qt.QGuiApplication_Clipboard().SetText(val)
			d.status.SetText("copied: " + val)
		})
		h.AddWidget(btn.QWidget)
	}
	return row
}

// netcatCheatsheet opens the sheet matching the session's current port.
func (d *netcatWindow) netcatCheatsheet() {
	port, _ := strconv.Atoi(d.port.Text())
	d.u.openCheatsheet(cheatsheetForPort(port))
}

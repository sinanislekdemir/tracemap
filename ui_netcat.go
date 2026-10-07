package main

import (
	"fmt"
	"strconv"
	"strings"

	qt "github.com/mappu/miqt/qt6"
)

// netcatWindow is a floating interactive TCP session.
type netcatWindow struct {
	u          *uiApp
	id         string
	win        *qt.QDialog
	out        *qt.QPlainTextEdit
	in         *qt.QLineEdit
	host       *qt.QLineEdit
	port       *qt.QLineEdit
	timeout    *qt.QSpinBox
	sni        *qt.QLineEdit
	tls        *qt.QCheckBox
	connect    *qt.QPushButton
	disconnect *qt.QPushButton
}

func (u *uiApp) openNetcat() { u.openNetcatFor("", 0, false) }

// openNetcatFor opens a session window, optionally prefilled and auto-connected
// (used from port-scan results).
func (u *uiApp) openNetcatFor(host string, port int, tls bool) {
	d := &netcatWindow{u: u}
	d.win = newFloatingDialog(u.win.QWidget)
	d.win.SetWindowTitle("Netcat")
	d.win.Resize(640, 460)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	form := qt.NewQFormLayout2()
	d.host = qt.NewQLineEdit2()
	d.host.SetPlaceholderText("host")
	d.port = qt.NewQLineEdit2()
	d.port.SetPlaceholderText("port")
	d.timeout = qt.NewQSpinBox2()
	d.timeout.SetRange(1000, 120000)
	d.timeout.SetSingleStep(1000)
	d.timeout.SetValue(10000)
	d.timeout.SetSuffix(" ms")
	d.sni = qt.NewQLineEdit2()
	d.sni.SetPlaceholderText("(defaults to host, ignored for IP literals)")
	d.tls = qt.NewQCheckBox3("TLS")
	form.AddRow3("Host", d.host.QWidget)
	form.AddRow3("Port", d.port.QWidget)
	form.AddRow3("Timeout", d.timeout.QWidget)
	form.AddRow3("TLS name", d.sni.QWidget)
	form.AddRow3("", d.tls.QWidget)
	v.AddLayout(form.QLayout)

	buttons := qt.NewQWidget2()
	bh := qt.NewQHBoxLayout(buttons)
	bh.SetContentsMargins(0, 0, 0, 0)
	d.connect = newButton("Connect", func() { d.start() })
	d.disconnect = newButton("Disconnect", func() { d.disconnectSession() })
	d.disconnect.SetEnabled(false)
	bh.AddWidget(d.connect.QWidget)
	bh.AddWidget(d.disconnect.QWidget)
	bh.AddStretch()
	v.AddWidget(buttons)

	d.out = qt.NewQPlainTextEdit2()
	d.out.SetReadOnly(true)
	d.out.SetMaximumBlockCount(4000)
	d.out.SetFont(monoFont())
	v.AddWidget2(d.out.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	d.in = qt.NewQLineEdit2()
	d.in.SetPlaceholderText("type a line and press enter")
	d.in.OnReturnPressed(func() { d.send() })
	send := newButton("Send", func() { d.send() })
	cheat := newButton("Cheatsheet", func() { d.netcatCheatsheet() })
	h.AddWidget(d.in.QWidget)
	h.AddWidget(send.QWidget)
	h.AddWidget(cheat.QWidget)
	v.AddWidget(row)

	if u.netcats == nil {
		u.netcats = map[string]*netcatWindow{}
	}
	if host != "" {
		d.host.SetText(host)
	}
	if port > 0 {
		d.port.SetText(fmt.Sprintf("%d", port))
	}
	d.tls.SetChecked(tls)
	// Closing the window must tear down a live session, not leak its socket.
	d.win.OnFinished(func(int) { d.closeSession() })
	d.win.Show()
	d.win.Raise()
	if host != "" && port > 0 {
		d.start()
	}
}

func (d *netcatWindow) start() {
	if d.id != "" {
		return
	}
	host := strings.TrimSpace(d.host.Text())
	port, err := strconv.Atoi(strings.TrimSpace(d.port.Text()))
	if host == "" || err != nil {
		d.out.AppendPlainText("enter a valid host and port")
		return
	}
	sess, err := d.u.app.NetConnect(NetConnectRequest{
		Host: host, Port: port, TimeoutMs: d.timeout.Value(), TLS: d.tls.IsChecked(),
		ServerName: strings.TrimSpace(d.sni.Text()),
	})
	if err != nil {
		d.out.AppendPlainText("connect: " + err.Error())
		return
	}
	d.id = sess.ID
	d.u.netcats[d.id] = d
	d.connect.SetEnabled(false)
	d.disconnect.SetEnabled(true)
	d.out.AppendPlainText(fmt.Sprintf("connected to %s:%d (tls=%v)", host, port, d.tls.IsChecked()))
}

// disconnectSession closes the live session; the net:closed event updates the UI.
func (d *netcatWindow) disconnectSession() {
	if d.id == "" {
		return
	}
	if err := d.u.app.NetClose(d.id); err != nil {
		d.out.AppendPlainText("disconnect: " + err.Error())
	}
}

// closeSession tears down a session when the window closes and drops it from
// the registry so a late event cannot touch a dead window.
func (d *netcatWindow) closeSession() {
	id := d.id
	if id != "" {
		_ = d.u.app.NetClose(id)
	}
	if d.u.netcats != nil {
		delete(d.u.netcats, id)
	}
	d.id = ""
}

func (d *netcatWindow) send() {
	if d.id == "" {
		return
	}
	line := d.in.Text()
	d.in.Clear()
	d.out.AppendPlainText("> " + line)
	if err := d.u.app.NetSend(d.id, line+"\n"); err != nil {
		d.out.AppendPlainText("send: " + err.Error())
	}
}

func (u *uiApp) onNetData(ev NetDataEvent) {
	d := u.netcats[ev.Session]
	if d == nil {
		return
	}
	d.out.AppendPlainText(strings.TrimRight(string(ev.Data), "\r\n"))
}

func (u *uiApp) onNetClosed(ev NetClosedEvent) {
	d := u.netcats[ev.Session]
	if d == nil {
		return
	}
	d.out.AppendPlainText("[closed] " + ev.Reason)
	d.connect.SetEnabled(true)
	if d.disconnect != nil {
		d.disconnect.SetEnabled(false)
	}
	d.id = ""
	delete(u.netcats, ev.Session)
}

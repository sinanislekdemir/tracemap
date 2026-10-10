package main

import (
	"fmt"
	"strconv"
	"strings"

	qt "github.com/mappu/miqt/qt6"
)

// netcatEOLs are the line endings the Netcat window can append to a sent line,
// in selector order.
var netcatEOLs = []struct {
	label  string
	ending string
}{
	{"LF (\\n)", "\n"},
	{"CRLF (\\r\\n)", "\r\n"},
	{"CR (\\r)", "\r"},
	{"None", ""},
}

// netcatWindow is a floating interactive TCP session. The terminal pane is one
// editable QPlainTextEdit: everything up to inputStart is scrollback; the text
// after it is the line the user is currently typing. Remote output is inserted
// before the input line so it always appears above what is being typed.
type netcatWindow struct {
	u          *uiApp
	id         string
	win        *qt.QDialog
	out        *qt.QPlainTextEdit
	eol        *qt.QComboBox
	host       *qt.QLineEdit
	port       *qt.QLineEdit
	timeout    *qt.QSpinBox
	sni        *qt.QLineEdit
	tls        *qt.QCheckBox
	connect    *qt.QPushButton
	disconnect *qt.QPushButton

	inputStart int
	history    []string
	histIdx    int

	// suppressClamp disables the cursor clamp while the terminal edits the
	// document itself.
	suppressClamp bool

	// Output-filter state, carried across net:data chunks so an escape sequence
	// or a CR split over two reads is still handled.
	pendingCR bool
	escState  int
}

func (u *uiApp) openNetcat() { u.openNetcatFor("", 0, false) }

// openNetcatFor opens a session window, optionally prefilled and auto-connected
// (used from port-scan results).
func (u *uiApp) openNetcatFor(host string, port int, tls bool) *netcatWindow {
	d := &netcatWindow{u: u}
	d.win = newFloatingDialog(u.win.QWidget)
	d.win.SetWindowTitle("Netcat")
	d.win.Resize(720, 500)
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

	d.eol = qt.NewQComboBox2()
	for _, e := range netcatEOLs {
		d.eol.AddItem(e.label)
	}
	if u.netcatEOL >= 0 && u.netcatEOL < len(netcatEOLs) {
		d.eol.SetCurrentIndex(u.netcatEOL)
	}
	d.eol.SetMinimumWidth(96)
	d.eol.SetToolTip("Line ending appended to each line you send")
	d.eol.OnCurrentIndexChanged(func(i int) { u.netcatEOL = i })
	bh.AddWidget(qt.NewQLabel3("EOL").QWidget)
	bh.AddWidget(d.eol.QWidget)

	cheat := newButton("Cheatsheet", func() { d.netcatCheatsheet() })
	bh.AddWidget(cheat.QWidget)
	copyCmd := newButton("Copy netcat command", func() { d.copyNetcatCommand() })
	copyCmd.SetToolTip("Copy an equivalent nc/ncat command to the clipboard (ncat --ssl for TLS)")
	bh.AddWidget(copyCmd.QWidget)
	v.AddWidget(buttons)

	// One editable pane that behaves like a line-mode terminal.
	d.out = qt.NewQPlainTextEdit2()
	applyTerminalStyle(d.out)
	d.out.SetUndoRedoEnabled(false)
	d.out.SetTabChangesFocus(false)
	d.out.SetPlaceholderText("type here and press Enter")
	d.out.OnKeyPressEvent(func(super func(e *qt.QKeyEvent), e *qt.QKeyEvent) {
		if d.onKey(e) {
			return
		}
		super(e)
	})
	d.out.OnCursorPositionChanged(func() { d.clampCursor() })
	v.AddWidget2(d.out.QWidget, 1)

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
	d.out.SetFocus()
	d.printLine("traceroute map · netcat — type a line and press Enter (EOL: " + d.eolLabel() + ")")
	if host != "" && port > 0 {
		d.start()
	}
	return d
}

func (d *netcatWindow) eolLabel() string {
	if d.eol == nil {
		return ""
	}
	i := d.eol.CurrentIndex()
	if i < 0 || i >= len(netcatEOLs) {
		return ""
	}
	return netcatEOLs[i].label
}

// lineEnding returns the byte sequence the EOL selector appends to a sent line.
func (d *netcatWindow) lineEnding() string {
	if d.eol == nil {
		return "\n"
	}
	i := d.eol.CurrentIndex()
	if i < 0 || i >= len(netcatEOLs) {
		return "\n"
	}
	return netcatEOLs[i].ending
}

func (d *netcatWindow) start() {
	if d.id != "" {
		return
	}
	host := strings.TrimSpace(d.host.Text())
	port, err := strconv.Atoi(strings.TrimSpace(d.port.Text()))
	if host == "" || err != nil {
		d.printLine("enter a valid host and port")
		return
	}
	sess, err := d.u.app.NetConnect(NetConnectRequest{
		Host: host, Port: port, TimeoutMs: d.timeout.Value(), TLS: d.tls.IsChecked(),
		ServerName: strings.TrimSpace(d.sni.Text()),
	})
	if err != nil {
		d.printLine("connect: " + err.Error())
		return
	}
	d.id = sess.ID
	d.u.netcats[d.id] = d
	d.connect.SetEnabled(false)
	d.disconnect.SetEnabled(true)
	d.printLine(fmt.Sprintf("connected to %s:%d (tls=%v)", host, port, d.tls.IsChecked()))
	d.out.SetFocus()
}

// disconnectSession closes the live session; the net:closed event updates the UI.
func (d *netcatWindow) disconnectSession() {
	if d.id == "" {
		return
	}
	if err := d.u.app.NetClose(d.id); err != nil {
		d.printLine("disconnect: " + err.Error())
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

// ---- terminal input ----

// onKey handles keystrokes the terminal interprets itself; it returns true when
// the key was consumed. Everything else falls through to QPlainTextEdit so
// typing, selection and paste keep working.
func (d *netcatWindow) onKey(e *qt.QKeyEvent) bool {
	mods := e.Modifiers()
	ctrl := mods&qt.ControlModifier != 0
	switch {
	case ctrl && e.Key() == int(qt.Key_C):
		// Copy when something is selected (Ctrl+C / Ctrl+Shift+C), otherwise
		// send the interrupt byte, like a real terminal.
		if mods&qt.ShiftModifier != 0 || d.out.TextCursor().HasSelection() {
			return false
		}
		d.sendRaw("\x03")
		return true
	case ctrl && e.Key() == int(qt.Key_D):
		d.sendRaw("\x04") // EOT / EOF
		return true
	case ctrl && e.Key() == int(qt.Key_U):
		d.setInput("")
		return true
	case ctrl && e.Key() == int(qt.Key_L):
		d.clearTerminal()
		return true
	}

	switch e.Key() {
	case int(qt.Key_Return), int(qt.Key_Enter):
		d.submit()
		return true
	case int(qt.Key_Backspace):
		if d.out.TextCursor().Position() <= d.inputStart {
			return true // never delete scrollback
		}
	case int(qt.Key_Left), int(qt.Key_Home):
		c := d.out.TextCursor()
		if !c.HasSelection() && c.Position() <= d.inputStart {
			return true
		}
	case int(qt.Key_Up):
		d.recall(-1)
		return true
	case int(qt.Key_Down):
		d.recall(1)
		return true
	}
	return false
}

// inputText returns the current (editable) input line.
func (d *netcatWindow) inputText() string {
	c := d.out.TextCursor()
	c.SetPosition(d.inputStart)
	c.MovePosition(qt.QTextCursor__End)
	end := c.Position()
	c.SetPosition(d.inputStart)
	c.SetPosition2(end, qt.QTextCursor__KeepAnchor)
	return c.SelectedText()
}

// setInput replaces the current input line and puts the caret at its end.
func (d *netcatWindow) setInput(text string) {
	d.suppressClamp = true
	c := d.out.TextCursor()
	c.SetPosition(d.inputStart)
	c.MovePosition(qt.QTextCursor__End)
	end := c.Position()
	c.SetPosition(d.inputStart)
	c.SetPosition2(end, qt.QTextCursor__KeepAnchor)
	c.InsertText(text)
	d.out.SetTextCursor(c)
	d.suppressClamp = false
}

// submit sends the current input line and commits it to the scrollback.
func (d *netcatWindow) submit() {
	line := d.inputText()
	if d.id == "" {
		d.printLine("[not connected]")
		return
	}
	if err := d.u.app.NetSend(d.id, line+d.lineEnding()); err != nil {
		d.printLine("send: " + err.Error())
		return
	}
	if line != "" {
		d.history = append(d.history, line)
	}
	d.histIdx = len(d.history)

	// Commit: append a newline and move the input region past it.
	d.suppressClamp = true
	c := d.out.TextCursor()
	c.SetPosition(d.inputStart)
	c.MovePosition(qt.QTextCursor__End)
	c.InsertText("\n")
	d.inputStart = c.Position()
	d.out.SetTextCursor(c)
	d.suppressClamp = false
	d.out.EnsureCursorVisible()
}

// recall walks the input history (dir -1 = older, +1 = newer).
func (d *netcatWindow) recall(dir int) {
	if len(d.history) == 0 {
		return
	}
	idx := d.histIdx + dir
	if idx < 0 {
		idx = 0
	}
	if idx > len(d.history) {
		idx = len(d.history)
	}
	d.histIdx = idx
	if idx == len(d.history) {
		d.setInput("")
		return
	}
	d.setInput(d.history[idx])
}

// clampCursor keeps the caret inside the editable input region. It leaves a
// selection alone so scrollback text can still be selected and copied.
func (d *netcatWindow) clampCursor() {
	if d.suppressClamp {
		return
	}
	c := d.out.TextCursor()
	if c.HasSelection() || c.Position() >= d.inputStart {
		return
	}
	c.SetPosition(d.inputStart)
	d.suppressClamp = true
	d.out.SetTextCursor(c)
	d.suppressClamp = false
}

// clearTerminal wipes the screen and restarts the input region.
func (d *netcatWindow) clearTerminal() {
	d.suppressClamp = true
	d.out.Clear()
	d.inputStart = 0
	d.suppressClamp = false
}

// ---- terminal output ----

// appendOutput inserts text just before the input line, so remote output always
// appears above whatever the user is typing.
func (d *netcatWindow) appendOutput(text string) {
	if text == "" || d.out == nil {
		return
	}
	atBottom := d.atBottom()
	d.suppressClamp = true
	cur := d.out.TextCursor().Position()
	oldStart := d.inputStart

	c := d.out.TextCursor()
	c.SetPosition(oldStart)
	c.InsertText(text)
	newEnd := c.Position()
	d.inputStart = newEnd
	if cur >= oldStart {
		cur += newEnd - oldStart
	}
	c.SetPosition(cur)
	d.out.SetTextCursor(c)
	d.suppressClamp = false

	if atBottom {
		d.out.EnsureCursorVisible()
	}
}

// printLine writes a local status line into the terminal.
func (d *netcatWindow) printLine(s string) {
	d.appendOutput(s + "\n")
}

// sendRaw sends raw bytes (used for control keys such as Ctrl+C) to the session.
func (d *netcatWindow) sendRaw(data string) {
	if d.id == "" {
		return
	}
	if err := d.u.app.NetSend(d.id, data); err != nil {
		d.printLine("send: " + err.Error())
	}
}

func (d *netcatWindow) atBottom() bool {
	sb := d.out.VerticalScrollBar()
	if sb == nil {
		return true
	}
	return sb.Value() >= sb.Maximum()-2
}

// filterOutput turns a raw read into printable terminal text: it strips ANSI
// escape sequences and other control characters, and normalises CRLF/CR to a
// newline. State is carried across chunks.
func (d *netcatWindow) filterOutput(s string) string {
	var b strings.Builder
	for _, r := range s {
		if d.escState != 0 {
			switch d.escState {
			case 1: // just saw ESC
				switch r {
				case '[':
					d.escState = 2
				case ']':
					d.escState = 3
				default:
					d.escState = 0
				}
			case 2: // CSI: consume until a final byte in 0x40..0x7e
				if r >= 0x40 && r <= 0x7e {
					d.escState = 0
				}
			case 3: // OSC: consume until BEL or ESC
				if r == 0x07 {
					d.escState = 0
				} else if r == 0x1b {
					d.escState = 4
				}
			case 4: // ESC inside an OSC: consume the terminator
				d.escState = 0
			}
			continue
		}
		switch {
		case r == 0x1b:
			d.escState = 1
		case r == '\r':
			d.pendingCR = true
		default:
			if d.pendingCR {
				b.WriteByte('\n')
				d.pendingCR = false
				if r == '\n' {
					continue // CRLF collapses to one newline
				}
			}
			switch {
			case r == '\n' || r == '\t':
				b.WriteRune(r)
			case r >= 0x20:
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// copyNetcatCommand copies an equivalent command for a real terminal — nc for a
// plain session, ncat --ssl for TLS — to the clipboard.
func (d *netcatWindow) copyNetcatCommand() {
	cmd := d.netcatCommand()
	if cmd == "" {
		d.printLine("enter a host and port first")
		return
	}
	qt.QGuiApplication_Clipboard().SetText(cmd)
	d.printLine("$ " + cmd + "   (copied to clipboard)")
}

func (d *netcatWindow) netcatCommand() string {
	host := strings.TrimSpace(d.host.Text())
	port := strings.TrimSpace(d.port.Text())
	if host == "" || port == "" {
		return ""
	}
	if d.tls.IsChecked() {
		cmd := "ncat --ssl " + shellArg(host) + " " + port
		if sni := strings.TrimSpace(d.sni.Text()); sni != "" && sni != host {
			cmd += " --ssl-servername " + shellArg(sni)
		}
		return cmd
	}
	return "nc " + shellArg(host) + " " + port
}

// shellArg quotes an argument for a POSIX shell when it contains characters the
// shell would otherwise interpret.
func shellArg(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$&|;<>(){}[]*?!#~`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (u *uiApp) onNetData(ev NetDataEvent) {
	d := u.netcats[ev.Session]
	if d == nil {
		return
	}
	d.appendOutput(d.filterOutput(string(ev.Data)))
}

func (u *uiApp) onNetClosed(ev NetClosedEvent) {
	d := u.netcats[ev.Session]
	if d == nil {
		return
	}
	d.printLine("[closed] " + ev.Reason)
	d.connect.SetEnabled(true)
	if d.disconnect != nil {
		d.disconnect.SetEnabled(false)
	}
	d.id = ""
	delete(u.netcats, ev.Session)
}

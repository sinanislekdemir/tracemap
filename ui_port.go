package main

import (
	"fmt"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"

	"traceroute/internal/hostscan"
	"traceroute/internal/portscan"
)

// portDialog is the port-scanner window: options, a live results table and an
// activity log. It owns its own event stream (portscan:*).
type portDialog struct {
	u           *uiApp
	win         *qt.QDialog
	target      string
	label       string
	cidr        string
	proto       *qt.QComboBox
	preset      *qt.QComboBox
	rangeE      *qt.QLineEdit
	scope       *qt.QComboBox
	concurrency *qt.QSpinBox
	timeout     *qt.QSpinBox
	probe       *qt.QCheckBox
	table       *qt.QTreeWidget
	activity    *qt.QPlainTextEdit
	open        int
	opens       []PortOpenEvent

	lastReq    PortScanRequest
	startedAt  time.Time
	finishedAt time.Time
	scanned    int
	targets    int
}

func (u *uiApp) openPortScanDialog() {
	u.openPortScanFor(strings.TrimSpace(u.target.Text()), "")
}

func (u *uiApp) openPortScanFor(host, label string) {
	d := &portDialog{u: u}
	d.build(host, label)
	u.portDlg = d
	d.win.Show()
	d.win.Raise()
	d.win.ActivateWindow()
}

func (d *portDialog) build(host, label string) {
	d.target = host
	d.label = label
	explicitPorts := ""
	if cidr, ports, ok := parseBlockTarget(host); ok {
		d.cidr = cidr
		d.target = cidr
		explicitPorts = ports
	}

	d.win = newFloatingDialog(d.u.win.QWidget)
	d.win.SetWindowTitle("Port scan · " + d.target)
	d.win.Resize(720, 560)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	form := qt.NewQFormLayout2()
	if d.cidr != "" {
		form.AddRow3("Block", qt.NewQLabel3(d.cidr).QWidget)
	} else {
		form.AddRow3("Host", qt.NewQLabel3(d.target).QWidget)
	}

	d.proto = qt.NewQComboBox2()
	d.proto.AddItems([]string{"tcp", "udp"})
	form.AddRow3("Protocol", d.proto.QWidget)

	d.concurrency = qt.NewQSpinBox2()
	d.concurrency.SetRange(1, 1024)
	d.concurrency.SetValue(128)
	form.AddRow3("Concurrency", d.concurrency.QWidget)

	d.timeout = qt.NewQSpinBox2()
	d.timeout.SetRange(100, 30000)
	d.timeout.SetSingleStep(100)
	d.timeout.SetValue(1500)
	d.timeout.SetSuffix(" ms")
	form.AddRow3("Timeout", d.timeout.QWidget)

	d.preset = qt.NewQComboBox2()
	d.preset.AddItems([]string{"top20", "top100", "top1000", "custom"})
	d.preset.SetCurrentIndex(1)
	form.AddRow3("Preset", d.preset.QWidget)

	d.rangeE = qt.NewQLineEdit2()
	d.rangeE.SetPlaceholderText("e.g. 22,80,443-445")
	form.AddRow3("Custom range", d.rangeE.QWidget)

	// A ":ports" suffix on the target wins over the preset.
	if explicitPorts != "" {
		d.preset.SetCurrentIndex(3)
		d.rangeE.SetText(explicitPorts)
	}

	// Scope: this host, or every target the last scan produced.
	if d.cidr == "" && len(d.u.scanTargets) > 0 {
		d.scope = qt.NewQComboBox2()
		d.scope.AddItem("This host")
		d.scope.AddItem(fmt.Sprintf("All targets (%d)", len(d.u.scanTargets)))
		form.AddRow3("Scope", d.scope.QWidget)
	}

	d.probe = qt.NewQCheckBox3("Identify services (banner/HTTP/TLS)")
	d.probe.SetChecked(true)
	form.AddRow3("", d.probe.QWidget)
	v.AddLayout(form.QLayout)

	start := newButton("Start", func() { d.start() })
	cancel := newButton("Cancel", func() { d.u.app.CancelPortScan() })
	export := newButton("Export report", func() { d.exportReport() })
	btnRow := qt.NewQWidget2()
	btnRowLayout := qt.NewQHBoxLayout(btnRow)
	btnRowLayout.SetContentsMargins(0, 0, 0, 0)
	btnRowLayout.AddWidget(start.QWidget)
	btnRowLayout.AddWidget(cancel.QWidget)
	btnRowLayout.AddWidget(export.QWidget)
	btnRowLayout.AddStretch()
	v.AddWidget(btnRow)

	d.table = qt.NewQTreeWidget2()
	d.table.SetColumnCount(5)
	d.table.SetHeaderLabels([]string{"Host", "Port", "Proto", "Service", "Detail"})
	d.table.OnItemDoubleClicked(func(item *qt.QTreeWidgetItem, col int) { d.openNetcat(item) })
	d.table.SetContextMenuPolicy(qt.CustomContextMenu)
	d.table.OnCustomContextMenuRequested(func(pos *qt.QPoint) { d.resultMenu(pos) })
	v.AddWidget2(d.table.QWidget, 1)

	d.activity = qt.NewQPlainTextEdit2()
	d.activity.SetReadOnly(true)
	d.activity.SetMaximumBlockCount(2000)
	d.activity.SetFont(monoFont())
	d.activity.SetMaximumHeight(140)
	v.AddWidget(d.activity.QWidget)
}

func (d *portDialog) start() {
	req := PortScanRequest{
		Host:        d.target,
		Protocol:    d.proto.CurrentText(),
		Preset:      d.preset.CurrentText(),
		PortRange:   strings.TrimSpace(d.rangeE.Text()),
		Concurrency: d.concurrency.Value(),
		TimeoutMs:   d.timeout.Value(),
		Probe:       d.probe.IsChecked(),
	}
	switch {
	case d.cidr != "":
		req.CIDR = d.cidr
	case d.scope != nil && d.scope.CurrentIndex() == 1 && len(d.u.scanTargets) > 0:
		req.Targets = append([]PortScanTarget(nil), d.u.scanTargets...)
	}
	d.lastReq = req
	d.startedAt = time.Now()
	d.finishedAt = time.Time{}
	d.scanned = 0
	if req.CIDR != "" {
		if network, ok := hostscan.ParseCIDR(req.CIDR); ok {
			d.targets = int(hostscan.Count(network))
		}
	} else if len(req.Targets) > 0 {
		d.targets = len(req.Targets)
	} else {
		d.targets = 1
	}
	// A port scan is independent of the map: never clear the traces.
	d.table.Clear()
	d.activity.Clear()
	d.open = 0
	d.opens = nil
	d.activity.AppendPlainText(fmt.Sprintf("scanning %s (%s/%s)…", d.describeScope(), req.Protocol, req.Preset))
	d.u.startOp("portscan " + d.target)
	go func() {
		if err := d.u.app.ScanPorts(req); err != nil {
			mainthread.Start(func() { d.u.status.ShowMessage(err.Error()) })
		}
	}()
}

// finish records the scan's completion so an export can report its duration.
func (d *portDialog) finish(e PortScanDoneEvent) {
	d.finishedAt = time.Now()
	d.scanned = e.Scanned
	if e.Targets > 0 {
		d.targets = e.Targets
	}
	d.activity.AppendPlainText(fmt.Sprintf("done · %d open across %d target(s)", e.Open, d.targets))
}

// fail records an aborted scan in the activity log.
func (d *portDialog) fail(message string) {
	d.finishedAt = time.Now()
	d.activity.AppendPlainText("error: " + message)
}

// describeScope renders the scan scope for the activity log.
func (d *portDialog) describeScope() string {
	if d.lastReq.CIDR != "" {
		return d.lastReq.CIDR
	}
	if len(d.lastReq.Targets) > 1 {
		return fmt.Sprintf("%d targets", len(d.lastReq.Targets))
	}
	return d.target
}

// exportReport assembles the scan context and open ports and writes a report.
func (d *portDialog) exportReport() {
	req := d.lastReq
	if req.Protocol == "" {
		req = PortScanRequest{Host: d.target, Protocol: d.proto.CurrentText(), Preset: d.preset.CurrentText()}
	}
	ports := d.portLabel(req)
	report := PortScanReport{
		Target:      d.target,
		Scope:       d.scopeLabel(req),
		StartedAt:   d.startedAt.UnixMilli(),
		DurationMs:  d.durationMs(),
		Protocol:    req.Protocol,
		Ports:       ports,
		PortCount:   portCount(req),
		Probe:       req.Probe,
		Concurrency: req.Concurrency,
		TimeoutMs:   req.TimeoutMs,
		Scanned:     d.scanned,
		Open:        len(d.opens),
		Targets:     d.targets,
		Rows:        d.reportRows(),
	}
	switch {
	case req.CIDR != "":
		// A block report lists hosts from the rows; no explicit target list.
	case len(req.Targets) > 0:
		for _, t := range req.Targets {
			report.ResolvedTargets = append(report.ResolvedTargets, PortScanTargetInfo{Label: t.Label, Host: t.Host})
		}
	default:
		label := d.label
		if label == "" {
			label = d.target
		}
		report.ResolvedTargets = []PortScanTargetInfo{{Label: label, Host: d.target}}
	}
	if _, err := d.u.app.ExportPortScanReport(report); err != nil {
		d.u.status.ShowMessage(err.Error())
	}
}

func (d *portDialog) durationMs() int64 {
	end := d.finishedAt
	if end.IsZero() {
		end = time.Now()
	}
	if d.startedAt.IsZero() || end.Before(d.startedAt) {
		return 0
	}
	return end.Sub(d.startedAt).Milliseconds()
}

// scopeLabel names the scan's target scope for the report.
func (d *portDialog) scopeLabel(req PortScanRequest) string {
	switch {
	case req.CIDR != "":
		return fmt.Sprintf("block (%d hosts)", d.targets)
	case len(req.Targets) > 1:
		return fmt.Sprintf("all targets (%d)", len(req.Targets))
	default:
		return "single host"
	}
}

// portLabel names the scanned port set (preset name, or the custom range).
func (d *portDialog) portLabel(req PortScanRequest) string {
	if spec := strings.TrimSpace(req.PortRange); spec != "" {
		return spec
	}
	if preset := strings.TrimSpace(req.Preset); preset != "" {
		return preset
	}
	return "custom"
}

// reportRows converts the collected open-port events into report rows.
func (d *portDialog) reportRows() []PortScanRow {
	rows := make([]PortScanRow, 0, len(d.opens))
	for _, ev := range d.opens {
		r := ev.Result
		rows = append(rows, PortScanRow{
			Host: ev.Host, Label: ev.Label, Port: r.Port, Protocol: r.Protocol,
			Service: r.Service, Product: r.Product, Detail: r.Detail, Banner: r.Banner,
			TLS: r.TLS, FTPAnonymous: r.FTPAnonymous,
		})
	}
	return rows
}

// portCount resolves how many ports a request scans.
func portCount(req PortScanRequest) int {
	if spec := strings.TrimSpace(req.PortRange); spec != "" {
		if ports, err := portscan.ParsePorts(spec); err == nil {
			return len(ports)
		}
		return 0
	}
	if preset := strings.TrimSpace(req.Preset); preset != "" {
		if ports, err := portscan.PresetPorts(preset); err == nil {
			return len(ports)
		}
	}
	return 0
}

func (d *portDialog) addOpen(ev PortOpenEvent) {
	item := qt.NewQTreeWidgetItem3(d.table)
	item.SetText(0, ev.Host)
	item.SetText(1, fmt.Sprintf("%d", ev.Result.Port))
	item.SetText(2, ev.Result.Protocol)
	item.SetText(3, ev.Result.Service)
	detail := ev.Result.Product
	if ev.Result.Banner != "" {
		detail = strings.TrimSpace(detail + " " + ev.Result.Banner)
	}
	anon := ftpAnonymousLabel(ev.Result.FTPAnonymous)
	if anon != "" {
		detail = strings.TrimSpace(detail + " · " + anon)
	}
	item.SetText(4, detail)
	if anon != "" {
		item.SetForeground(4, qt.NewQBrush3(qt.NewQColor6(ftpAnonymousColor(ev.Result.FTPAnonymous))))
	}
	d.open++
	d.opens = append(d.opens, ev)
	line := fmt.Sprintf("OPEN %s:%d/%s %s", ev.Host, ev.Result.Port, ev.Result.Protocol, ev.Result.Service)
	if anon != "" {
		line += " · " + anon
	}
	d.activity.AppendPlainText(line)
}

// ftpAnonymousLabel renders the tri-state anonymous-FTP verdict, or "" when no
// FTP login was attempted.
func ftpAnonymousLabel(allowed *bool) string {
	switch {
	case allowed == nil:
		return ""
	case *allowed:
		return "anonymous FTP ALLOWED"
	default:
		return "anonymous FTP required"
	}
}

// ftpAnonymousColor highlights an allowed anonymous login, since it is a
// security finding.
func ftpAnonymousColor(allowed *bool) string {
	if allowed != nil && *allowed {
		return "#ff6b6b"
	}
	return "#3ddc97"
}

// rowFor maps a result row back to its open-port event.
func (d *portDialog) rowFor(item *qt.QTreeWidgetItem) (PortOpenEvent, bool) {
	if item == nil {
		return PortOpenEvent{}, false
	}
	idx := d.table.IndexOfTopLevelItem(item)
	if idx < 0 || idx >= len(d.opens) {
		return PortOpenEvent{}, false
	}
	return d.opens[idx], true
}

// openNetcat starts an interactive session for a result row (double-click).
func (d *portDialog) openNetcat(item *qt.QTreeWidgetItem) {
	ev, ok := d.rowFor(item)
	if !ok {
		return
	}
	d.u.openNetcatFor(ev.Host, ev.Result.Port, ev.Result.TLS)
}

// resultMenu offers per-port actions.
func (d *portDialog) resultMenu(pos *qt.QPoint) {
	item := d.table.ItemAt(pos)
	ev, ok := d.rowFor(item)
	if !ok {
		return
	}
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Netcat…", func() { d.u.openNetcatFor(ev.Host, ev.Result.Port, ev.Result.TLS) })
	addMenuAction(menu, "Trace this host", func() { d.u.traceHost(ev.Host) })
	addMenuAction(menu, "Copy IP", func() { qt.QGuiApplication_Clipboard().SetText(ev.Host) })
	gp := d.table.MapToGlobal(qt.NewQPointF3(float64(pos.X()), float64(pos.Y())))
	menu.ExecWithPos(qt.NewQPoint2(int(gp.X()), int(gp.Y())))
}

func (u *uiApp) onPortOpen(ev PortOpenEvent) {
	if u.portDlg != nil {
		u.portDlg.addOpen(ev)
	}
	if ev.Result.Service == "" && ev.Result.FTPAnonymous == nil {
		return
	}
	line := fmt.Sprintf("%s:%d/%s %s", ev.Host, ev.Result.Port, ev.Result.Protocol, ev.Result.Service)
	if anon := ftpAnonymousLabel(ev.Result.FTPAnonymous); anon != "" {
		line += " · " + anon
	}
	u.openChannel("ports").line("ok", line)
}

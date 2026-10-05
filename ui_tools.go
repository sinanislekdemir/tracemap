package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"

	"traceroute/internal/domaincheck"
	"traceroute/internal/geolocator"
	"traceroute/internal/httpcheck"
	"traceroute/internal/origin"
	"traceroute/internal/portscan"
)

// cleanDomain strips a scheme and any path from the target box.
func cleanDomain(input string) string {
	d := strings.TrimSpace(input)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	return d
}

func textDialog(title string, w, h int) (*qt.QDialog, *qt.QTextBrowser) {
	dlg := newFloatingDialog()
	dlg.SetWindowTitle(title)
	dlg.Resize(w, h)
	v := qt.NewQVBoxLayout(dlg.QWidget)
	tb := qt.NewQTextBrowser2()
	v.AddWidget2(tb.QWidget, 1)
	return dlg, tb
}

// ---- domain analysis ----

type domainDialog struct {
	u       *uiApp
	win     *qt.QDialog
	summary *qt.QLabel
	status  *qt.QLabel
	tabs    *qt.QTabWidget
	checks  *qt.QTreeWidget
	reg     *qt.QTreeWidget
	dns     *qt.QTreeWidget
	web     *qt.QTreeWidget
	report  domaincheck.Report
}

// cleanDomain strips a scheme and any path from the target box.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func mark(v bool) string {
	if v {
		return "✓"
	}
	return "·"
}

func fmtDateMs(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	return time.UnixMilli(ms).Format("2006-01-02")
}

func shortSHA(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	if s == "" {
		return "—"
	}
	return s
}

func statusColor(status string) string {
	switch status {
	case "pass":
		return "#3ddc97"
	case "warn":
		return "#f5b642"
	case "fail":
		return "#ff6b6b"
	default:
		return "#9db4c8"
	}
}

func verdictColor(v string) string {
	switch v {
	case "confirmed":
		return "#3ddc97"
	case "likely":
		return "#f5b642"
	case "dead":
		return "#ff6b6b"
	default:
		return "#9db4c8"
	}
}

func treeRow(tree *qt.QTreeWidget, key, value string) *qt.QTreeWidgetItem {
	it := qt.NewQTreeWidgetItem3(tree)
	it.SetText(0, key)
	it.SetText(1, value)
	return it
}

func treeGroup(tree *qt.QTreeWidget, title string) *qt.QTreeWidgetItem {
	it := qt.NewQTreeWidgetItem3(tree)
	it.SetText(0, title)
	return it
}

func childRow(parent *qt.QTreeWidgetItem, key, value string) {
	it := qt.NewQTreeWidgetItem6(parent)
	it.SetText(0, key)
	it.SetText(1, value)
}

// sectionTab builds a two-column tree configured as a report section page.
func sectionTab(title string) (*qt.QTreeWidget, *qt.QWidget) {
	tree := qt.NewQTreeWidget2()
	tree.SetColumnCount(2)
	tree.SetHeaderLabels([]string{title, ""})
	tree.SetColumnWidth(0, 190)
	return tree, tree.QWidget
}

func (u *uiApp) openDomainDialog() {
	domain := cleanDomain(u.target.Text())
	if domain == "" {
		u.status.ShowMessage("enter a domain first")
		return
	}
	d := &domainDialog{u: u}
	d.win = newFloatingDialog()
	d.win.SetWindowTitle("Domain analysis · " + domain)
	d.win.Resize(900, 680)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	d.summary = qt.NewQLabel3("analyzing " + domain + "…")
	f := qt.NewQFont()
	f.SetPointSize(11)
	f.SetBold(true)
	d.summary.SetFont(f)
	d.summary.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	v.AddWidget(d.summary.QWidget)

	d.status = qt.NewQLabel3("")
	d.status.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	v.AddWidget(d.status.QWidget)

	d.tabs = qt.NewQTabWidget2()

	d.checks = qt.NewQTreeWidget2()
	d.checks.SetColumnCount(3)
	d.checks.SetHeaderLabels([]string{"Status", "Check", "Detail"})
	d.checks.SetColumnWidth(0, 80)
	d.checks.SetColumnWidth(1, 260)
	d.checks.Header().SetStretchLastSection(true)
	d.tabs.AddTab(d.checks.QWidget, "Checklist")

	var page *qt.QWidget
	d.reg, page = sectionTab("Registration")
	d.tabs.AddTab(page, "Registration")
	d.dns, page = sectionTab("Record")
	d.tabs.AddTab(page, "DNS / Email")
	d.web, page = sectionTab("Header")
	d.tabs.AddTab(page, "Web / TLS")

	v.AddWidget2(d.tabs.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	export := newButton("Export report", func() {
		if d.report.Domain == "" {
			return
		}
		if _, err := u.app.ExportDomainReport(d.report); err != nil {
			u.status.ShowMessage(err.Error())
		}
	})
	h.AddWidget(export.QWidget)
	h.AddWidget(newButton("Cancel", func() { u.app.CancelDomainAnalysis() }).QWidget)
	h.AddStretch()
	h.AddWidget(newButton("Close", func() { d.win.Close() }).QWidget)
	v.AddWidget(row)

	u.domainDlg = d
	d.win.Show()
	d.win.Raise()

	go func() {
		report, err := u.app.AnalyzeDomain(domain)
		mainthread.Start(func() {
			if err != nil {
				d.status.SetText("error: " + err.Error())
				return
			}
			d.populate(report)
		})
	}()
}

func (d *domainDialog) populate(r domaincheck.Report) {
	d.report = r
	d.summary.SetText(fmt.Sprintf("%s   ·   grade %s  ·  score %d  ·  %s",
		r.Domain, r.Grade, r.Score, time.UnixMilli(r.AnalyzedAt).Format("2006-01-02 15:04")))
	d.status.SetText("")

	// Checklist, grouped by category.
	d.checks.Clear()
	for _, cat := range []string{"registration", "dns", "email", "web"} {
		var group *qt.QTreeWidgetItem
		for _, c := range r.Checks {
			if c.Category != cat {
				continue
			}
			if group == nil {
				group = treeGroup2(d.checks, strings.ToUpper(cat))
			}
			it := qt.NewQTreeWidgetItem6(group)
			it.SetText(0, strings.ToUpper(c.Status))
			it.SetForeground(0, qt.NewQBrush3(qt.NewQColor6(statusColor(c.Status))))
			it.SetText(1, c.Title)
			it.SetText(2, c.Detail)
		}
	}

	// Registration.
	d.reg.Clear()
	if reg := r.Registration; reg != nil && reg.Found {
		treeRow(d.reg, "Registrar", orDash(reg.Registrar))
		treeRow(d.reg, "Domain", orDash(reg.Domain))
		treeRow(d.reg, "Created", fmtDateMs(reg.CreatedAt))
		treeRow(d.reg, "Expires", fmt.Sprintf("%s (%d days)", fmtDateMs(reg.ExpiresAt), reg.DaysToExpiry))
		treeRow(d.reg, "Age", fmt.Sprintf("%d days", reg.AgeDays))
		if len(reg.Statuses) > 0 {
			treeRow(d.reg, "Statuses", strings.Join(reg.Statuses, ", "))
		}
		if len(reg.Nameservers) > 0 {
			treeRow(d.reg, "Nameservers", strings.Join(reg.Nameservers, ", "))
		}
		treeRow(d.reg, "Registrant", orDash(reg.Registrant))
		treeRow(d.reg, "Country", orDash(reg.Country))
		treeRow(d.reg, "DNSSEC", orDash(reg.DNSSEC))
		treeRow(d.reg, "Source", orDash(reg.Source))
	} else {
		treeRow(d.reg, "Registration", "not found")
		if reg != nil && reg.Error != "" {
			treeRow(d.reg, "Error", reg.Error)
		}
	}

	// DNS / email auth.
	d.dns.Clear()
	list := func(label string, vals []string) {
		if len(vals) > 0 {
			treeRow(d.dns, label, strings.Join(vals, ", "))
		}
	}
	list("Addresses", r.DNS.Addresses)
	list("Nameservers", r.DNS.Nameservers)
	list("MX", r.DNS.MX)
	if r.DNS.SPFPolicy != "" {
		treeRow(d.dns, "SPF policy", r.DNS.SPFPolicy)
	}
	list("SPF", r.DNS.SPF)
	if r.DNS.DMARCPolicy != "" {
		treeRow(d.dns, "DMARC policy", r.DNS.DMARCPolicy)
	}
	list("DMARC", r.DNS.DMARC)
	list("DMARC rua", r.DNS.DMARCRUA)
	list("DKIM", r.DNS.DKIM)
	list("MTA-STS", r.DNS.MTASTS)
	list("TLS-RPT", r.DNS.TLSRPT)
	list("CAA", r.DNS.CAA)
	treeRow(d.dns, "DNSKEY", yesNo(r.DNS.DNSKEY))
	treeRow(d.dns, "DS", yesNo(r.DNS.DS))
	if len(r.DNS.Records) > 0 {
		g := treeGroup(d.dns, "Raw records")
		for _, rec := range r.DNS.Records {
			childRow(g, rec.Type+"  "+rec.Name, rec.Value)
		}
	}

	// Web / TLS.
	d.web.Clear()
	w := r.Web
	treeRow(d.web, "URL", orDash(w.URL))
	treeRow(d.web, "HTTPS", yesNo(w.HTTPS))
	if w.HTTPStatus > 0 {
		treeRow(d.web, "HTTP status", fmt.Sprintf("%d", w.HTTPStatus))
	}
	treeRow(d.web, "Redirects to HTTPS", yesNo(w.RedirectsHTTPS))
	if w.TLSVersion != "" {
		treeRow(d.web, "TLS", w.TLSVersion)
	}
	treeRow(d.web, "Cert subject", orDash(w.CertSubject))
	treeRow(d.web, "Cert issuer", orDash(w.CertIssuer))
	if w.CertNotAfter > 0 {
		treeRow(d.web, "Cert expires", fmt.Sprintf("%s (%d days)", fmtDateMs(w.CertNotAfter), w.CertDaysLeft))
	}
	if w.Error != "" {
		treeRow(d.web, "Error", w.Error)
	}
	if len(w.Headers) > 0 {
		g := treeGroup(d.web, "Security headers")
		keys := make([]string, 0, len(w.Headers))
		for k := range w.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childRow(g, k, w.Headers[k])
		}
	}
	d.checks.ExpandAll()
}

// treeGroup2 is treeGroup with explicit column 0 only (group header).
func treeGroup2(tree *qt.QTreeWidget, title string) *qt.QTreeWidgetItem {
	it := qt.NewQTreeWidgetItem3(tree)
	it.SetText(0, title)
	return it
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func (u *uiApp) onDomainProgress(e DomainProgressEvent) {
	if u.domainDlg != nil && u.domainDlg.status != nil {
		u.domainDlg.status.SetText(e.Phase + ": " + e.Message)
	}
}

// ---- origin (unmask) ----

type originDialog struct {
	u          *uiApp
	win        *qt.QDialog
	summary    *qt.QLabel
	rulesLabel *qt.QLabel
	custom     *qt.QCheckBox
	log        *qt.QPlainTextEdit
	tabs       *qt.QTabWidget
	cand       *qt.QTreeWidget
	base       *qt.QTreeWidget
	last       origin.Report
}

func (u *uiApp) openOriginDialog() {
	domain := cleanDomain(u.target.Text())
	if domain == "" {
		u.status.ShowMessage("enter a domain first")
		return
	}
	d := &originDialog{u: u}
	d.win = newFloatingDialog()
	d.win.SetWindowTitle("Unmask target · " + domain)
	d.win.Resize(960, 700)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	d.summary = qt.NewQLabel3("unmasking " + domain + "…")
	f := qt.NewQFont()
	f.SetPointSize(11)
	f.SetBold(true)
	d.summary.SetFont(f)
	d.summary.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	v.AddWidget(d.summary.QWidget)

	// Custom intermediary-marker rules: opt-in, with a file to maintain.
	rulesInfo := u.app.UnmaskRulesPath()
	d.custom = qt.NewQCheckBox3("Use custom rules")
	rulesRow := qt.NewQWidget2()
	rh := qt.NewQHBoxLayout(rulesRow)
	rh.SetContentsMargins(0, 0, 0, 0)
	rh.SetSpacing(6)
	rh.AddWidget(d.custom.QWidget)
	d.rulesLabel = qt.NewQLabel3(unmaskRulesSummary(rulesInfo))
	d.rulesLabel.SetWordWrap(true)
	d.rulesLabel.SetSizePolicy2(qt.QSizePolicy__Expanding, qt.QSizePolicy__Preferred)
	rh.AddWidget2(d.rulesLabel.QWidget, 1)
	create := newButton("Create rules file", func() { d.createRules() })
	rh.AddWidget(create.QWidget)
	v.AddWidget(rulesRow)

	d.tabs = qt.NewQTabWidget2()

	d.cand = qt.NewQTreeWidget2()
	d.cand.SetColumnCount(9)
	d.cand.SetHeaderLabels([]string{"IP", "Verdict", "Score", "Ports", "Cert", "Body", "Favicon", "Status", "Note"})
	d.cand.SetColumnWidth(0, 130)
	d.cand.SetColumnWidth(1, 90)
	d.cand.SetColumnWidth(2, 50)
	d.cand.SetColumnWidth(3, 90)
	d.cand.Header().SetStretchLastSection(true)
	d.tabs.AddTab(d.cand.QWidget, "Candidates")

	var page *qt.QWidget
	d.base, page = sectionTab("Field")
	d.tabs.AddTab(page, "Baseline")

	d.log = qt.NewQPlainTextEdit2()
	d.log.SetReadOnly(true)
	d.log.SetMaximumBlockCount(4000)
	d.log.SetFont(monoFont())
	d.tabs.AddTab(d.log.QWidget, "Live log")

	v.AddWidget2(d.tabs.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	export := newButton("Export report", func() {
		if d.last.Domain == "" {
			return
		}
		if _, err := u.app.ExportOriginReport(d.last); err != nil {
			u.status.ShowMessage(err.Error())
		}
	})
	h.AddWidget(export.QWidget)
	h.AddWidget(newButton("Cancel", func() { u.app.CancelUnmaskTarget() }).QWidget)
	h.AddStretch()
	h.AddWidget(newButton("Close", func() { d.win.Close() }).QWidget)
	v.AddWidget(row)

	u.originDlg = d
	d.win.Show()
	d.win.Raise()

	customRules := d.custom.IsChecked()
	go func() {
		report, err := u.app.UnmaskTarget(domain, customRules)
		mainthread.Start(func() {
			if err != nil {
				d.log.AppendPlainText("error: " + err.Error())
				return
			}
			d.populate(report)
			u.addOriginMarkers(report)
		})
	}()
}

// unmaskRulesSummary describes the user's rules file and whether it exists.
func unmaskRulesSummary(info UnmaskRulesInfo) string {
	if info.Path == "" {
		return "custom rules: no config directory available"
	}
	state := "not created yet"
	if info.Exists {
		state = "ready"
	}
	return fmt.Sprintf("custom rules file · %s · %s", state, info.Path)
}

// createRules writes the built-in marker rules to the user's rules file and
// refreshes the dialog's state.
func (d *originDialog) createRules() {
	path, err := d.u.app.CreateUnmaskRules()
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	d.rulesLabel.SetText(unmaskRulesSummary(d.u.app.UnmaskRulesPath()))
	if path != "" && d.custom != nil {
		d.custom.SetChecked(true)
	}
	d.u.status.ShowMessage("rules file written to " + path)
}

func (d *originDialog) populate(r origin.Report) {
	d.last = r
	confirmed, likely := 0, 0
	for _, o := range r.Origins {
		switch string(o.Verdict) {
		case "confirmed":
			confirmed++
		case "likely":
			likely++
		}
	}
	d.summary.SetText(fmt.Sprintf("%s   ·   %d confirmed  ·  %d likely  ·  %d candidates  ·  proxied: %s",
		r.Domain, confirmed, likely, len(r.Candidates), yesNo(r.Baseline.Proxied)))

	byIP := map[string]origin.Origin{}
	for _, o := range r.Origins {
		byIP[o.IP] = o
	}
	rows := r.Candidates
	if len(rows) == 0 {
		for _, o := range r.Origins {
			rows = append(rows, origin.Candidate{IP: o.IP})
		}
	}
	d.cand.Clear()
	for _, c := range rows {
		o := byIP[c.IP]
		verdict := string(o.Verdict)
		if verdict == "" {
			verdict = "—"
		}
		it := qt.NewQTreeWidgetItem3(d.cand)
		it.SetText(0, c.IP)
		it.SetText(1, verdict)
		it.SetForeground(1, qt.NewQBrush3(qt.NewQColor6(verdictColor(verdict))))
		it.SetText(2, fmt.Sprintf("%d", o.Score))
		it.SetText(3, portsString(o.Ports))
		it.SetText(4, mark(o.Evidence.CertMatch))
		it.SetText(5, mark(o.Evidence.BodyMatch))
		it.SetText(6, mark(o.Evidence.FaviconMatch))
		it.SetText(7, mark(o.Evidence.StatusMatch))
		note := o.Note
		if len(c.Hostnames) > 0 {
			note = strings.TrimSpace(strings.Join(c.Hostnames, ", ") + " " + note)
		}
		it.SetText(8, note)
		it.SetToolTip(0, strings.Join(c.Sources, ", "))
	}

	// Baseline.
	d.base.Clear()
	b := r.Baseline
	treeRow(d.base, "Proxied", yesNo(b.Proxied))
	list := func(label string, vals []string) {
		if len(vals) > 0 {
			treeRow(d.base, label, strings.Join(vals, ", "))
		}
	}
	list("Proxied IPs", b.ProxiedIPs)
	list("Markers", b.Markers)
	if b.Status > 0 {
		treeRow(d.base, "HTTP status", fmt.Sprintf("%d", b.Status))
	}
	treeRow(d.base, "Cert subject", orDash(b.Cert.Subject))
	treeRow(d.base, "Cert issuer", orDash(b.Cert.Issuer))
	treeRow(d.base, "Cert SHA-256", shortSHA(b.Cert.SHA256))
	treeRow(d.base, "Favicon SHA", shortSHA(b.FaviconSHA))
	treeRow(d.base, "Body SHA", shortSHA(b.BodySHA))
	if len(b.Headers) > 0 {
		g := treeGroup(d.base, "Headers")
		keys := make([]string, 0, len(b.Headers))
		for k := range b.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childRow(g, k, b.Headers[k])
		}
	}
	if len(r.Notes) > 0 {
		g := treeGroup(d.base, "Notes")
		for _, n := range r.Notes {
			childRow(g, "", n)
		}
	}
}

func portsString(ports []int) string {
	if len(ports) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	return strings.Join(parts, ",")
}

func (u *uiApp) addOriginMarkers(report origin.Report) {
	for _, o := range report.Origins {
		if o.Verdict != origin.VerdictConfirmed && o.Verdict != origin.VerdictLikely {
			continue
		}
		if !o.Geo.Resolved {
			continue
		}
		u.origins = append(u.origins, originMarker{
			IP: o.IP, Lat: o.Geo.Lat, Lon: o.Geo.Lon, Verdict: string(o.Verdict), Label: report.Domain,
		})
	}
	u.refreshMap()
}

func (u *uiApp) onOriginProgress(e OriginProgressEvent) {
	if u.originDlg != nil && u.originDlg.log != nil {
		u.originDlg.log.AppendPlainText(fmt.Sprintf("%s: %s", e.Phase, e.Message))
	}
}

func (u *uiApp) onOriginLog(e OriginLogEvent) {
	if u.originDlg != nil && u.originDlg.log != nil {
		u.originDlg.log.AppendPlainText(e.Message)
	}
}

// ---- endpoint analysis ----

type endpointDialog struct {
	u        *uiApp
	win      *qt.QDialog
	summary  *qt.QLabel
	list     *qt.QTreeWidget
	tabs     *qt.QTabWidget
	overview *qt.QTreeWidget
	checks   *qt.QTreeWidget
	headers  *qt.QTreeWidget
	cookies  *qt.QTreeWidget
	cache    *qt.QTreeWidget
	tech     *qt.QTreeWidget
	tls      *qt.QTreeWidget
	redirect *qt.QTreeWidget
	log      *qt.QPlainTextEdit
	reports  []httpcheck.Report
	selected int

	scopeTarget *qt.QCheckBox
	scopeSubs   *qt.QCheckBox
	scopeCrawl  *qt.QCheckBox
	scopePorts  *qt.QCheckBox
}

func gradeColor(grade string) string {
	switch grade {
	case "A", "A+", "A-", "B", "B+", "B-":
		return "#3ddc97"
	case "C", "C+", "C-":
		return "#f5b642"
	case "D", "D+", "D-", "E", "F":
		return "#ff6b6b"
	default:
		return "#9db4c8"
	}
}

func (u *uiApp) openEndpointDialog() {
	target := cleanDomain(u.target.Text())
	if target == "" {
		u.status.ShowMessage("enter a host first")
		return
	}
	d := &endpointDialog{u: u, selected: -1}
	d.win = newFloatingDialog()
	d.win.SetWindowTitle("Endpoint analysis · " + target)
	d.win.Resize(1000, 720)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	d.summary = qt.NewQLabel3("analyzing https://" + target + "…")
	f := qt.NewQFont()
	f.SetPointSize(11)
	f.SetBold(true)
	d.summary.SetFont(f)
	d.summary.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	v.AddWidget(d.summary.QWidget)

	// Scope: pick which discovered endpoints to analyze in bulk.
	d.scopeTarget = qt.NewQCheckBox3("Entered target")
	d.scopeTarget.SetChecked(true)
	scopeRow := qt.NewQWidget2()
	sr := qt.NewQHBoxLayout(scopeRow)
	sr.SetContentsMargins(0, 0, 0, 0)
	sr.SetSpacing(10)
	sr.AddWidget(qt.NewQLabel3("Analyze:").QWidget)
	sr.AddWidget(d.scopeTarget.QWidget)
	d.scopeSubs = qt.NewQCheckBox3(fmt.Sprintf("Subdomains (%d)", len(u.subs)))
	d.scopeSubs.SetEnabled(len(u.subs) > 0)
	sr.AddWidget(d.scopeSubs.QWidget)
	d.scopeCrawl = qt.NewQCheckBox3(fmt.Sprintf("Crawled pages (%d)", len(u.crawlPages)))
	d.scopeCrawl.SetEnabled(len(u.crawlPages) > 0)
	sr.AddWidget(d.scopeCrawl.QWidget)
	portEPs := u.portEndpoints()
	d.scopePorts = qt.NewQCheckBox3(fmt.Sprintf("Port services (%d)", len(portEPs)))
	d.scopePorts.SetEnabled(len(portEPs) > 0)
	sr.AddWidget(d.scopePorts.QWidget)
	sr.AddStretch()
	v.AddWidget(scopeRow)

	split := qt.NewQSplitter3(qt.Horizontal)

	d.list = qt.NewQTreeWidget2()
	d.list.SetColumnCount(4)
	d.list.SetHeaderLabels([]string{"Endpoint", "Grade", "Score", "Status"})
	d.list.SetColumnWidth(0, 200)
	d.list.SetColumnWidth(1, 55)
	d.list.SetColumnWidth(2, 55)
	d.list.OnItemClicked(func(item *qt.QTreeWidgetItem, col int) { d.selectByItem(item) })
	split.AddWidget(d.list.QWidget)

	d.tabs = qt.NewQTabWidget2()
	newTab := func(label string, cols []string, widths []int) *qt.QTreeWidget {
		t := qt.NewQTreeWidget2()
		t.SetColumnCount(len(cols))
		t.SetHeaderLabels(cols)
		for i, w := range widths {
			t.SetColumnWidth(i, w)
		}
		t.Header().SetStretchLastSection(true)
		d.tabs.AddTab(t.QWidget, label)
		return t
	}
	d.overview = newTab("Overview", []string{"Field", "Value"}, []int{180})
	d.checks = newTab("Checklist", []string{"Status", "Check", "Detail"}, []int{80, 240})
	d.headers = newTab("Headers", []string{"Header", "Value", "Kind"}, []int{180, 260})
	d.cookies = newTab("Cookies", []string{"Cookie", "Secure", "HttpOnly", "SameSite", "Tech"}, []int{150, 60, 70, 90})
	d.cache = newTab("Caching", []string{"Field", "Value"}, []int{180})
	d.tech = newTab("Tech", []string{"Name", "Category", "Evidence"}, []int{160, 110})
	d.tls = newTab("TLS", []string{"Field", "Value"}, []int{180})
	d.redirect = newTab("Redirects", []string{"From", "To", "Status"}, []int{220})

	d.log = qt.NewQPlainTextEdit2()
	d.log.SetReadOnly(true)
	d.log.SetMaximumBlockCount(4000)
	d.log.SetFont(monoFont())
	d.tabs.AddTab(d.log.QWidget, "Log")

	split.AddWidget(d.tabs.QWidget)
	split.SetSizes([]int{320, 680})
	split.SetStretchFactor(0, 0)
	split.SetStretchFactor(1, 1)
	v.AddWidget2(split.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	export := newButton("Export report", func() {
		if len(d.reports) == 0 {
			return
		}
		if _, err := u.app.ExportHTTPReport(d.reports); err != nil {
			u.status.ShowMessage(err.Error())
		}
	})
	h.AddWidget(export.QWidget)
	h.AddWidget(newButton("Analyze", func() { d.startAnalysis(target, portEPs) }).QWidget)
	h.AddWidget(newButton("Cancel", func() { u.app.CancelEndpointAnalysis() }).QWidget)
	h.AddStretch()
	h.AddWidget(newButton("Close", func() { d.win.Close() }).QWidget)
	v.AddWidget(row)

	u.endpointDlg = d
	d.win.Show()
	d.win.Raise()
	d.startAnalysis(target, portEPs)
}

// startAnalysis analyzes the endpoints selected by the scope checkboxes.
func (d *endpointDialog) startAnalysis(target string, portEPs []EndpointTarget) {
	targets := d.scopeTargets(target, portEPs)
	if len(targets) == 0 {
		d.log.AppendPlainText("no endpoints selected")
		return
	}
	d.reports = nil
	d.selected = -1
	d.list.Clear()
	d.log.Clear()
	d.log.AppendPlainText(fmt.Sprintf("analyzing %d endpoint(s)…", len(targets)))
	go func() {
		reports, err := d.u.app.AnalyzeEndpoints(EndpointAnalysisRequest{Targets: targets})
		mainthread.Start(func() {
			if err != nil {
				d.log.AppendPlainText("error: " + err.Error())
				return
			}
			if len(reports) > 0 {
				d.reports = reports
				d.refreshList()
				d.selectIndex(0)
			}
		})
	}()
}

// scopeTargets expands the ticked scopes into a concrete endpoint batch.
func (d *endpointDialog) scopeTargets(target string, portEPs []EndpointTarget) []EndpointTarget {
	var out []EndpointTarget
	if d.scopeTarget.IsChecked() {
		out = append(out, EndpointTarget{URL: "https://" + target, Label: target, Source: "manual"})
	}
	if d.scopeSubs.IsChecked() {
		for _, s := range d.u.subs {
			out = append(out, EndpointTarget{URL: "https://" + s.Name, Label: s.Name, Source: "subdomain"})
		}
	}
	if d.scopeCrawl.IsChecked() {
		for _, pg := range d.u.crawlPages {
			if pg.URL != "" {
				out = append(out, EndpointTarget{URL: pg.URL, Label: pg.URL, Source: "crawl"})
			}
		}
	}
	if d.scopePorts.IsChecked() {
		out = append(out, portEPs...)
	}
	return out
}

// portEndpoints collects HTTP(S) endpoints from the open port-scan dialog, so
// they can be analyzed in bulk.
func (u *uiApp) portEndpoints() []EndpointTarget {
	if u.portDlg == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []EndpointTarget
	for _, ev := range u.portDlg.opens {
		if !isHTTPService(ev.Result) {
			continue
		}
		scheme := "http"
		if ev.Result.TLS {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s:%d", scheme, ev.Host, ev.Result.Port)
		if seen[url] {
			continue
		}
		seen[url] = true
		label := ev.Label
		if label == "" {
			label = ev.Host
		}
		out = append(out, EndpointTarget{URL: url, Label: label, Source: "ports"})
	}
	return out
}

// isHTTPService reports whether a port-scan result looks like an HTTP server.
func isHTTPService(r portscan.Result) bool {
	if r.TLS {
		return true
	}
	switch strings.ToLower(r.Service) {
	case "http", "https", "http-alt", "http-proxy":
		return true
	}
	switch r.Port {
	case 80, 443, 8000, 8080, 8443, 8888:
		return true
	}
	return false
}

func (d *endpointDialog) refreshList() {
	d.list.Clear()
	best := ""
	for _, r := range d.reports {
		it := qt.NewQTreeWidgetItem3(d.list)
		it.SetText(0, r.URL)
		it.SetText(1, r.Grade)
		it.SetForeground(1, qt.NewQBrush3(qt.NewQColor6(gradeColor(r.Grade))))
		it.SetText(2, fmt.Sprintf("%d", r.Score))
		if r.Status > 0 {
			it.SetText(3, fmt.Sprintf("%d", r.Status))
		} else {
			it.SetText(3, "—")
		}
		best = r.Grade
	}
	n := len(d.reports)
	plural := "endpoint"
	if n != 1 {
		plural = "endpoints"
	}
	d.summary.SetText(fmt.Sprintf("%d %s analyzed   ·   grade %s", n, plural, orDash(best)))
	if d.selected >= 0 && d.selected < n {
		if item := d.list.TopLevelItem(d.selected); item != nil {
			d.list.SetCurrentItem(item)
		}
	}
}

func (d *endpointDialog) selectByItem(item *qt.QTreeWidgetItem) {
	if item == nil {
		return
	}
	url := item.Text(0)
	for i, r := range d.reports {
		if r.URL == url {
			d.selectIndex(i)
			return
		}
	}
}

func (d *endpointDialog) selectIndex(i int) {
	if i < 0 || i >= len(d.reports) {
		return
	}
	d.selected = i
	r := d.reports[i]

	d.overview.Clear()
	treeRow(d.overview, "URL", orDash(r.URL))
	if r.FinalURL != "" && r.FinalURL != r.URL {
		treeRow(d.overview, "Final URL", r.FinalURL)
	}
	treeRow(d.overview, "Host", orDash(r.Host))
	treeRow(d.overview, "Grade", r.Grade)
	treeRow(d.overview, "Score", fmt.Sprintf("%d", r.Score))
	treeRow(d.overview, "HTTPS", yesNo(r.HTTPS))
	if r.Status > 0 {
		treeRow(d.overview, "HTTP status", fmt.Sprintf("%d", r.Status))
	}
	treeRow(d.overview, "Content type", orDash(r.ContentType))
	treeRow(d.overview, "Server", orDash(r.Server))
	if r.BodySize > 0 {
		sz := fmt.Sprintf("%d bytes", r.BodySize)
		if r.Truncated {
			sz += " (truncated)"
		}
		treeRow(d.overview, "Body", sz)
	}
	if r.AnalyzedAt > 0 {
		treeRow(d.overview, "Analyzed", time.UnixMilli(r.AnalyzedAt).Format("2006-01-02 15:04"))
	}
	if r.Error != "" {
		treeRow(d.overview, "Error", r.Error)
	}

	d.checks.Clear()
	for _, c := range r.Checks {
		it := qt.NewQTreeWidgetItem3(d.checks)
		it.SetText(0, strings.ToUpper(c.Status))
		it.SetForeground(0, qt.NewQBrush3(qt.NewQColor6(statusColor(c.Status))))
		it.SetText(1, c.Title)
		it.SetText(2, c.Detail)
	}

	d.headers.Clear()
	for _, hd := range r.Headers {
		it := qt.NewQTreeWidgetItem3(d.headers)
		it.SetText(0, hd.Name)
		it.SetText(1, hd.Value)
		it.SetText(2, hd.Kind)
		it.SetForeground(2, qt.NewQBrush3(qt.NewQColor6(headerKindColor(hd.Kind))))
	}

	d.cookies.Clear()
	for _, ck := range r.Cookies {
		it := qt.NewQTreeWidgetItem3(d.cookies)
		it.SetText(0, ck.Name)
		it.SetText(1, mark(ck.Secure))
		it.SetText(2, mark(ck.HTTPOnly))
		it.SetText(3, orDash(ck.SameSite))
		it.SetText(4, orDash(ck.Tech))
		it.SetToolTip(0, ck.Value)
	}

	d.cache.Clear()
	ca := r.Caching
	treeRow(d.cache, "Cache-Control", orDash(ca.CacheControl))
	if len(ca.Directives) > 0 {
		treeRow(d.cache, "Directives", strings.Join(ca.Directives, ", "))
	}
	treeRow(d.cache, "Cacheable", yesNo(ca.Cacheable))
	treeRow(d.cache, "Shared", yesNo(ca.Shared))
	treeRow(d.cache, "Public", yesNo(ca.Public))
	treeRow(d.cache, "Private", yesNo(ca.Private))
	treeRow(d.cache, "No-store", yesNo(ca.NoStore))
	treeRow(d.cache, "No-cache", yesNo(ca.NoCache))
	if ca.MaxAge > 0 {
		treeRow(d.cache, "Max-Age", fmt.Sprintf("%d s", ca.MaxAge))
	}
	if ca.SMaxAge > 0 {
		treeRow(d.cache, "s-Max-Age", fmt.Sprintf("%d s", ca.SMaxAge))
	}
	if ca.Age > 0 {
		treeRow(d.cache, "Age", fmt.Sprintf("%d s", ca.Age))
	}
	treeRow(d.cache, "ETag", orDash(ca.ETag))
	treeRow(d.cache, "Last-Modified", orDash(ca.LastModified))
	treeRow(d.cache, "Pragma", orDash(ca.Pragma))
	treeRow(d.cache, "Expires", orDash(ca.Expires))
	if len(ca.Vary) > 0 {
		treeRow(d.cache, "Vary", strings.Join(ca.Vary, ", "))
	}
	treeRow(d.cache, "CDN", orDash(ca.CDN))

	d.tech.Clear()
	for _, t := range r.Tech {
		it := qt.NewQTreeWidgetItem3(d.tech)
		it.SetText(0, t.Name)
		it.SetText(1, t.Category)
		it.SetText(2, t.Evidence)
	}

	d.tls.Clear()
	if r.TLS == nil {
		treeRow(d.tls, "TLS", "no TLS handshake captured")
	} else {
		t := r.TLS
		ver := t.Version
		if t.ALPN != "" {
			ver += " / " + t.ALPN
		}
		treeRow(d.tls, "Version", orDash(ver))
		treeRow(d.tls, "Cipher", orDash(t.Cipher))
		treeRow(d.tls, "Subject", orDash(t.Subject))
		treeRow(d.tls, "Issuer", orDash(t.Issuer))
		if t.NotAfter > 0 {
			treeRow(d.tls, "Expires", fmt.Sprintf("%s (%d days)", fmtDateMs(t.NotAfter), t.DaysLeft))
		}
		if len(t.SANs) > 0 {
			g := treeGroup(d.tls, "SANs")
			for _, san := range t.SANs {
				childRow(g, "", san)
			}
		}
	}

	d.redirect.Clear()
	for _, rd := range r.Redirects {
		it := qt.NewQTreeWidgetItem3(d.redirect)
		it.SetText(0, rd.From)
		it.SetText(1, rd.To)
		it.SetText(2, fmt.Sprintf("%d", rd.Status))
	}
}

func headerKindColor(kind string) string {
	switch kind {
	case "security":
		return "#3ddc97"
	case "cache":
		return "#f5b642"
	case "cors":
		return "#c4b5fd"
	case "cookie":
		return "#f472b6"
	case "info":
		return "#2dd4ef"
	default:
		return "#9db4c8"
	}
}

func (u *uiApp) onEndpointProgress(e EndpointProgressEvent) {
	if u.endpointDlg == nil {
		return
	}
	u.endpointDlg.summary.SetText(fmt.Sprintf("analyzed %d/%d endpoints…", e.Done, e.Total))
}

func (u *uiApp) onEndpointLog(e EndpointLogEvent) {
	if u.endpointDlg != nil && u.endpointDlg.log != nil {
		u.endpointDlg.log.AppendPlainText(fmt.Sprintf("%s  %-5s %s", e.URL, strings.ToUpper(e.Level), e.Message))
	}
}

func (u *uiApp) onEndpointResult(report httpcheck.Report) {
	if u.endpointDlg == nil {
		return
	}
	d := u.endpointDlg
	for i, existing := range d.reports {
		if existing.URL == report.URL {
			d.reports[i] = report
			d.refreshList()
			if d.selected < 0 {
				d.selectIndex(i)
			}
			return
		}
	}
	d.reports = append(d.reports, report)
	d.refreshList()
	if d.selected < 0 {
		d.selectIndex(len(d.reports) - 1)
	}
}

// ---- geo cache ----

type geocacheDialog struct {
	u       *uiApp
	win     *qt.QDialog
	info    *qt.QLabel
	filter  *qt.QLineEdit
	tree    *qt.QTreeWidget
	entries []geolocator.CacheEntry
}

func (u *uiApp) openGeoCacheDialog() {
	d := &geocacheDialog{u: u}
	d.win = newFloatingDialog()
	d.win.SetWindowTitle("GeoIP cache")
	d.win.Resize(720, 520)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	d.info = qt.NewQLabel3("")
	v.AddWidget(d.info.QWidget)

	d.filter = qt.NewQLineEdit2()
	d.filter.SetPlaceholderText("filter by IP, city, country or ASN…")
	d.filter.OnTextChanged(func(string) { d.render() })
	v.AddWidget(d.filter.QWidget)

	d.tree = qt.NewQTreeWidget2()
	d.tree.SetColumnCount(5)
	d.tree.SetHeaderLabels([]string{"IP", "Lat", "Lon", "City", "ASN"})
	d.tree.SetContextMenuPolicy(qt.CustomContextMenu)
	d.tree.OnCustomContextMenuRequested(func(pos *qt.QPoint) { d.rowMenu(pos) })
	v.AddWidget2(d.tree.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	refresh := newButton("Refresh", func() { d.load() })
	del := newButton("Delete selected", func() { d.deleteSelected() })
	clear := newButton("Clear all", func() {
		if err := u.app.ClearGeoCache(); err != nil {
			u.status.ShowMessage(err.Error())
		}
		d.load()
	})
	h.AddWidget(refresh.QWidget)
	h.AddWidget(del.QWidget)
	h.AddWidget(clear.QWidget)
	h.AddStretch()
	v.AddWidget(row)

	u.geocacheDlg = d
	d.load()
	d.win.Show()
	d.win.Raise()
}

func (d *geocacheDialog) load() {
	entries, err := d.u.app.ListGeoCache()
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	d.entries = entries
	info := d.u.app.GeoCacheInfo()
	d.info.SetText(fmt.Sprintf("entries: %d · persistence: %v · %s", info.Count, info.Enabled, info.Path))
	d.render()
}

// render draws the entries matching the filter.
func (d *geocacheDialog) render() {
	filter := strings.ToLower(strings.TrimSpace(d.filter.Text()))
	d.tree.Clear()
	shown := 0
	for _, e := range d.entries {
		if filter != "" && !entryMatches(e, filter) {
			continue
		}
		item := qt.NewQTreeWidgetItem3(d.tree)
		item.SetText(0, e.IP)
		item.SetText(1, fmt.Sprintf("%.4f", e.Lat))
		item.SetText(2, fmt.Sprintf("%.4f", e.Lon))
		item.SetText(3, e.City)
		item.SetText(4, e.ASN)
		shown++
	}
	if len(d.entries) > 0 && shown == 0 {
		d.info.SetText(fmt.Sprintf("no entries match %q", filter))
	}
}

// entryMatches reports whether an entry contains the lower-cased filter text.
func entryMatches(e geolocator.CacheEntry, filter string) bool {
	haystack := strings.ToLower(strings.Join([]string{e.IP, e.City, e.Country, e.ASN}, " "))
	return strings.Contains(haystack, filter)
}

func (d *geocacheDialog) rowMenu(pos *qt.QPoint) {
	item := d.tree.ItemAt(pos)
	if item == nil {
		return
	}
	ip := item.Text(0)
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Copy IP", func() { qt.QGuiApplication_Clipboard().SetText(ip) })
	addMenuAction(menu, "Delete entry", func() { d.deleteIP(ip) })
	gp := d.tree.MapToGlobal(qt.NewQPointF3(float64(pos.X()), float64(pos.Y())))
	menu.ExecWithPos(qt.NewQPoint2(int(gp.X()), int(gp.Y())))
}

func (d *geocacheDialog) deleteSelected() {
	item := d.tree.CurrentItem()
	if item == nil {
		d.u.status.ShowMessage("select a cache entry first")
		return
	}
	d.deleteIP(item.Text(0))
}

func (d *geocacheDialog) deleteIP(ip string) {
	if err := d.u.app.DeleteGeoCacheEntry(ip); err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	d.u.status.ShowMessage("deleted " + ip)
	d.load()
}

// ---- country IP blocks ----

type ipblocksDialog struct {
	u           *uiApp
	win         *qt.QDialog
	countries   *qt.QTreeWidget
	blocks      *qt.QPlainTextEdit
	family      *qt.QComboBox
	filter      *qt.QLineEdit
	codes       map[string]string
	current     string
	currentName string
}

func (u *uiApp) openIPBlocksDialog() {
	d := &ipblocksDialog{u: u, codes: map[string]string{}}
	d.win = newFloatingDialog()
	d.win.SetWindowTitle("Country IP blocks")
	d.win.Resize(820, 620)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	info := u.app.IPBlocksInfo()
	infoLabel := qt.NewQLabel3(fmt.Sprintf("%s · %s · %s", info.Database, info.Build, info.Path))
	infoLabel.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	v.AddWidget(infoLabel.QWidget)

	// Filters: address family and a CIDR substring, both applied by the backend.
	controls := qt.NewQWidget2()
	ch := qt.NewQHBoxLayout(controls)
	ch.SetContentsMargins(0, 0, 0, 0)
	ch.SetSpacing(6)
	ch.AddWidget(qt.NewQLabel3("Family").QWidget)
	d.family = qt.NewQComboBox2()
	d.family.AddItems([]string{"All", "IPv4", "IPv6"})
	ch.AddWidget(d.family.QWidget)
	d.filter = qt.NewQLineEdit2()
	d.filter.SetPlaceholderText("filter CIDR (e.g. 10. or /16)")
	ch.AddWidget2(d.filter.QWidget, 1)
	v.AddWidget(controls)

	split := qt.NewQSplitter3(qt.Horizontal)
	d.countries = qt.NewQTreeWidget2()
	d.countries.SetColumnCount(3)
	d.countries.SetHeaderLabels([]string{"Country", "Blocks", "Addresses"})
	d.countries.SetColumnWidth(0, 160)
	d.countries.SetColumnWidth(1, 80)
	d.countries.Header().SetStretchLastSection(true)
	d.countries.OnItemClicked(func(item *qt.QTreeWidgetItem, col int) {
		if item != nil {
			d.selectCountry(item.Text(0))
		}
	})
	split.AddWidget(d.countries.QWidget)

	d.blocks = qt.NewQPlainTextEdit2()
	d.blocks.SetReadOnly(true)
	d.blocks.SetMaximumBlockCount(2000)
	split.AddWidget(d.blocks.QWidget)
	split.SetSizes([]int{280, 520})
	split.SetStretchFactor(0, 0)
	split.SetStretchFactor(1, 1)
	v.AddWidget2(split.QWidget, 1)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	refresh := newButton("Load countries", func() { d.loadCountries() })
	export := newButton("Export blocks", func() { d.exportBlocks() })
	h.AddWidget(refresh.QWidget)
	h.AddWidget(export.QWidget)
	h.AddStretch()
	v.AddWidget(row)

	d.family.OnCurrentIndexChanged(func(int) { d.onFilterChanged() })
	d.filter.OnTextChanged(func(string) { d.onFilterChanged() })

	// Releasing the cached walk when the window closes frees its memory.
	d.win.OnFinished(func(int) { u.app.ReleaseCountryBlocks() })

	u.ipblocksDlg = d
	d.loadCountries()
	d.win.Show()
	d.win.Raise()
}

// familyFromIndex maps the family combo index to the backend's ""/"ipv4"/"ipv6".
func familyFromIndex(idx int) string {
	switch idx {
	case 1:
		return "ipv4"
	case 2:
		return "ipv6"
	default:
		return ""
	}
}

// familyValue maps the family combo to the backend's ""/"ipv4"/"ipv6".
func (d *ipblocksDialog) familyValue() string { return familyFromIndex(d.family.CurrentIndex()) }

// onFilterChanged re-queries the selected country when a filter changes.
func (d *ipblocksDialog) onFilterChanged() {
	if d.current == "" {
		return
	}
	d.selectCountry(d.currentName)
}

// exportBlocks writes the selected country's blocks, honouring the filters, as
// a CIDR list.
func (d *ipblocksDialog) exportBlocks() {
	if d.current == "" {
		d.u.status.ShowMessage("select a country first")
		return
	}
	if _, err := d.u.app.ExportCountryBlocks(CountryBlocksRequest{
		Country: d.current, Family: d.familyValue(), Filter: strings.TrimSpace(d.filter.Text()),
	}); err != nil {
		d.u.status.ShowMessage(err.Error())
	}
}

func (d *ipblocksDialog) loadCountries() {
	d.countries.Clear()
	d.codes = map[string]string{}
	countries, err := d.u.app.ListCountryBlocks()
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	sort.SliceStable(countries, func(i, j int) bool {
		return strings.ToLower(countries[i].Name) < strings.ToLower(countries[j].Name)
	})
	for _, c := range countries {
		display := c.Name
		d.codes[display] = c.Code
		item := qt.NewQTreeWidgetItem3(d.countries)
		item.SetText(0, display)
		item.SetText(1, fmt.Sprintf("%d", c.Blocks))
		item.SetText(2, c.Addresses)
	}
}

// sortBlocksByNumber orders CIDR blocks by their numeric network address
// (IPv4 before IPv6, then by address bytes).
func sortBlocksByNumber(blocks []string) {
	sort.SliceStable(blocks, func(i, j int) bool {
		a, _, ea := net.ParseCIDR(blocks[i])
		b, _, eb := net.ParseCIDR(blocks[j])
		if ea != nil || eb != nil {
			return blocks[i] < blocks[j]
		}
		na, nb := a.To4(), b.To4()
		if na == nil {
			na = a.To16()
		}
		if nb == nil {
			nb = b.To16()
		}
		return bytes.Compare(na, nb) < 0
	})
}

func (d *ipblocksDialog) selectCountry(name string) {
	code := d.codes[name]
	d.current = code
	d.currentName = name
	family := d.familyValue()
	filter := strings.TrimSpace(d.filter.Text())
	d.blocks.SetPlainText("loading " + name + "…")
	go func() {
		res, err := d.u.app.QueryCountryBlocks(CountryBlocksRequest{
			Country: code, Family: family, Filter: filter, Limit: 2000,
		})
		mainthread.Start(func() {
			if err != nil {
				// A filter change cancels the previous query; ignore that.
				if errors.Is(err, context.Canceled) {
					return
				}
				d.blocks.SetPlainText("error: " + err.Error())
				return
			}
			blocks := append([]string(nil), res.Blocks...)
			sortBlocksByNumber(blocks)
			d.blocks.SetPlainText(fmt.Sprintf("%s · %d matched / %d total · %s\n\n%s",
				res.Country, res.Matched, res.Total, res.Addresses, strings.Join(blocks, "\n")))
		})
	}()
}

func (u *uiApp) onIPBlocksProgress(e IPBlocksProgressEvent) {
	u.status.ShowMessage(fmt.Sprintf("ipblocks %s %d/%d", e.Phase, e.Done, e.Total))
}

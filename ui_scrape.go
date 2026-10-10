package main

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"

	"traceroute/internal/httputil"
	"traceroute/internal/scrape"
)

// scrapeUserAgents is the User-Agent dropdown, in combo order.
var scrapeUserAgents = []struct{ Label, Value string }{
	{"Chrome", httputil.ChromeUserAgent},
	{"Firefox", httputil.FirefoxUserAgent},
	{"Edge", httputil.EdgeUserAgent},
	{"curl", httputil.CurlUserAgent},
}

// scrapeDialog is the scrape *run* window: targets, options, the live pages and
// media of the run, and its log. Browsing and searching the stored archive is a
// separate window (scrapeIndexDialog), opened from Tools ▸ Scrape ▸ Browse
// index.
type scrapeDialog struct {
	u   *uiApp
	win *qt.QDialog

	targets    []ScrapeTarget
	targetEdit *qt.QLineEdit
	scheme     *qt.QComboBox
	port       *qt.QSpinBox

	mode        *qt.QComboBox
	scope       *qt.QComboBox
	depth       *qt.QSpinBox
	maxPages    *qt.QSpinBox
	concurrency *qt.QSpinBox
	timeout     *qt.QSpinBox
	keywords    *qt.QLineEdit
	requireAll  *qt.QCheckBox
	indexTest   *qt.QCheckBox
	ignoreTLS   *qt.QCheckBox
	userAgent   *qt.QComboBox
	delaySec    *qt.QSpinBox
	delayEvery  *qt.QSpinBox

	startB  *qt.QPushButton
	cancelB *qt.QPushButton
	exportB *qt.QPushButton

	tabs         *qt.QTabWidget
	pageTable    *qt.QTreeWidget
	assetTable   *qt.QTreeWidget
	assetKind    *qt.QComboBox
	assetPreview *qt.QLabel
	leakTable    *qt.QTreeWidget

	log *qt.QPlainTextEdit

	pages  []scrape.PageSummary
	assets []scrape.AssetSummary
	leaks  []scrape.LeakSummary

	startedAt time.Time
	jobID     int64
	// filterActive is set when the run has a keyword filter, so the Pages list
	// refuses any page that was not indexed by that filter.
	filterActive bool
}

// openScrapeAddress opens the run window for whatever host is in the toolbar
// target box.
func (u *uiApp) openScrapeAddress() {
	target := strings.TrimSpace(u.target.Text())
	if target == "" {
		u.status.ShowMessage("enter a host in the target box first")
		return
	}
	if _, _, ok := parseBlockTarget(target); ok {
		u.status.ShowMessage("scrape works on a host or URL, not a CIDR block")
		return
	}
	u.openScrapeFor([]ScrapeTarget{scrapeTargetFromHost(target, target)}, "")
}

// openScrapeScanTargets opens the run window seeded with the last advanced
// scan's found targets (the same hosts the port-scan window offers as "All
// targets").
func (u *uiApp) openScrapeScanTargets() {
	if len(u.scanTargets) == 0 {
		u.status.ShowMessage("no scan targets yet — run a Scan first")
		return
	}
	targets := make([]ScrapeTarget, 0, len(u.scanTargets))
	for _, t := range u.scanTargets {
		label := strings.TrimSpace(t.Label)
		if label == "" {
			label = t.Host
		}
		targets = append(targets, scrapeTargetFromHost(label, t.Host))
	}
	u.openScrapeFor(targets, fmt.Sprintf("%d found scan targets", len(targets)))
}

// openScrapeFor opens the run window seeded with explicit targets.
func (u *uiApp) openScrapeFor(targets []ScrapeTarget, caption string) {
	if !u.app.ScrapeEnabled() {
		u.status.ShowMessage("scraping is disabled: no data directory (set TRACEROUTE_DATA)")
		return
	}
	d := &scrapeDialog{u: u, targets: targets}
	d.build(caption)
	u.scrapeDlg = d
	d.win.Show()
	d.win.Raise()
	d.win.ActivateWindow()
}

// scrapeTargetFromHost builds a target URL for a bare host or IP, defaulting to
// http:// when no scheme is present.
func scrapeTargetFromHost(label, host string) ScrapeTarget {
	host = strings.TrimSpace(host)
	return ScrapeTarget{Label: strings.TrimSpace(label), URL: host}
}

func (d *scrapeDialog) build(caption string) {
	d.win = newFloatingDialog(d.u.win.QWidget)
	d.win.SetWindowTitle("Scrape")
	d.win.Resize(920, 660)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	if caption != "" {
		head := qt.NewQLabel3(caption)
		head.SetWordWrap(true)
		v.AddWidget(head.QWidget)
	}

	form := qt.NewQFormLayout2()

	d.scheme = qt.NewQComboBox2()
	d.scheme.AddItems(scrapeSchemeTexts)
	d.port = qt.NewQSpinBox2()
	d.port.SetRange(0, 65535)
	d.port.SetSpecialValueText("default")
	d.port.SetValue(0)

	if len(d.targets) == 1 {
		spec := parseScrapeTarget(d.targets[0].URL)
		d.targetEdit = qt.NewQLineEdit2()
		d.targetEdit.SetText(spec.HostPath)
		d.targetEdit.SetPlaceholderText("hostname or IP (not a CIDR block)")
		d.scheme.SetCurrentIndex(schemeTextIndex(spec.Scheme))
		d.port.SetValue(spec.Port)
		form.AddRow3("Target", d.targetEdit.QWidget)
		form.AddRow3("Scheme", d.scheme.QWidget)
		form.AddRow3("Port", d.port.QWidget)
	} else {
		specs := make([]scrapeTargetSpec, len(d.targets))
		for i, t := range d.targets {
			specs[i] = parseScrapeTarget(t.URL)
		}
		if text, ok := commonSchemeText(specs); ok {
			d.scheme.SetCurrentIndex(schemeTextIndex(text))
		}
		d.port.SetValue(commonPort(specs))
		summary := qt.NewQLabel3(fmt.Sprintf("%d targets — scheme and port apply to every bare host; a target that already carries a URL keeps it", len(d.targets)))
		summary.SetWordWrap(true)
		form.AddRow3("Targets", summary.QWidget)
		form.AddRow3("Scheme", d.scheme.QWidget)
		form.AddRow3("Port", d.port.QWidget)
	}

	d.mode = qt.NewQComboBox2()
	d.mode.AddItems([]string{"html", "html+images", "html+media"})
	form.AddRow3("Download", d.mode.QWidget)

	d.scope = qt.NewQComboBox2()
	d.scope.AddItems([]string{"host", "site (subdomains)"})
	form.AddRow3("Follow links in", d.scope.QWidget)

	d.depth = qt.NewQSpinBox2()
	d.depth.SetRange(0, 10)
	d.depth.SetValue(scrape.DefaultDepth)
	form.AddRow3("Depth", d.depth.QWidget)

	d.maxPages = qt.NewQSpinBox2()
	d.maxPages.SetRange(1, 100000)
	d.maxPages.SetValue(scrape.DefaultMaxPages)
	form.AddRow3("Max indexed pages", d.maxPages.QWidget)

	d.concurrency = qt.NewQSpinBox2()
	d.concurrency.SetRange(1, 32)
	d.concurrency.SetValue(scrape.DefaultConcurrency)
	form.AddRow3("Concurrency", d.concurrency.QWidget)

	d.timeout = qt.NewQSpinBox2()
	d.timeout.SetRange(1000, 120000)
	d.timeout.SetSingleStep(1000)
	d.timeout.SetValue(15000)
	d.timeout.SetSuffix(" ms")
	form.AddRow3("Timeout", d.timeout.QWidget)

	d.keywords = qt.NewQLineEdit2()
	d.keywords.SetPlaceholderText("comma-separated keywords — only matching pages are stored")
	form.AddRow3("Keywords", d.keywords.QWidget)

	d.requireAll = qt.NewQCheckBox3("require every keyword (default: any)")
	form.AddRow3("", d.requireAll.QWidget)

	d.indexTest = qt.NewQCheckBox3("directory index test (probe for open listings)")
	d.indexTest.SetChecked(true)
	form.AddRow3("Recon", d.indexTest.QWidget)

	d.ignoreTLS = qt.NewQCheckBox3("ignore TLS errors (accept invalid/self-signed certs)")
	form.AddRow3("TLS", d.ignoreTLS.QWidget)

	d.userAgent = qt.NewQComboBox2()
	for _, ua := range scrapeUserAgents {
		d.userAgent.AddItem(ua.Label)
	}
	form.AddRow3("User agent", d.userAgent.QWidget)

	throttleRow := qt.NewQWidget2()
	th := qt.NewQHBoxLayout(throttleRow)
	th.SetContentsMargins(0, 0, 0, 0)
	d.delaySec = qt.NewQSpinBox2()
	d.delaySec.SetRange(0, 600)
	d.delaySec.SetToolTip("Seconds to pause after every N requests (0 = off)")
	d.delayEvery = qt.NewQSpinBox2()
	d.delayEvery.SetRange(0, 100000)
	d.delayEvery.SetToolTip("Pause after this many requests (0 = off)")
	th.AddWidget(qt.NewQLabel3("Wait").QWidget)
	th.AddWidget(d.delaySec.QWidget)
	th.AddWidget(qt.NewQLabel3("s every").QWidget)
	th.AddWidget(d.delayEvery.QWidget)
	th.AddWidget(qt.NewQLabel3("requests (0 = off)").QWidget)
	th.AddStretch()
	form.AddRow3("Throttle", throttleRow)

	v.AddLayout(form.QLayout)

	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)
	d.startB = newButton("Start scrape", func() { d.start() })
	d.cancelB = newButton("Cancel", func() { d.u.app.CancelScrape() })
	d.cancelB.SetEnabled(false)
	d.exportB = newButton("Export report", func() { d.export() })
	folder := newButton("Open archive folder", func() { d.openArchiveFolder() })
	h.AddWidget(d.startB.QWidget)
	h.AddWidget(d.cancelB.QWidget)
	h.AddWidget(d.exportB.QWidget)
	h.AddWidget(folder.QWidget)
	h.AddStretch()
	v.AddWidget(row)

	d.tabs = qt.NewQTabWidget2()
	v.AddWidget2(d.tabs.QWidget, 1)

	page := qt.NewQWidget2()
	pv := qt.NewQVBoxLayout(page)
	d.pageTable = newScrapePageTable(func(pos *qt.QPoint) { d.pageMenu(pos) }, func() { d.previewSelectedPage() })
	pv.AddWidget2(d.pageTable.QWidget, 1)
	d.tabs.AddTab(page, "Pages")

	d.tabs.AddTab(d.buildAssetsTab(), "Assets")

	leaks := qt.NewQWidget2()
	lv := qt.NewQVBoxLayout(leaks)
	d.leakTable = newScrapeLeakTable(func(pos *qt.QPoint) { d.leakMenu(pos) }, func() { d.openSelectedLeak() })
	lv.AddWidget2(d.leakTable.QWidget, 1)
	lv.AddWidget(qt.NewQLabel3("Directories that returned an open listing (autoindex).").QWidget)
	d.tabs.AddTab(leaks, "Leaks")

	d.log = qt.NewQPlainTextEdit2()
	d.log.SetReadOnly(true)
	d.log.SetMaximumBlockCount(3000)
	applyTerminalStyle(d.log)
	d.tabs.AddTab(d.log.QWidget, "Log")
}

func (d *scrapeDialog) buildAssetsTab() *qt.QWidget {
	assets := qt.NewQWidget2()
	av := qt.NewQVBoxLayout(assets)

	bar := qt.NewQWidget2()
	bh := qt.NewQHBoxLayout(bar)
	bh.SetContentsMargins(0, 0, 0, 0)
	bh.AddWidget(qt.NewQLabel3("Kind").QWidget)
	d.assetKind = qt.NewQComboBox2()
	d.assetKind.AddItems(scrapeAssetKinds())
	d.assetKind.OnCurrentIndexChanged(func(int) { d.renderAssets() })
	bh.AddWidget(d.assetKind.QWidget)
	bh.AddStretch()
	av.AddWidget(bar)

	d.assetTable = newScrapeAssetTable(
		func(pos *qt.QPoint) { d.assetMenu(pos) },
		func() { d.openSelectedAsset() },
		func() { d.updateAssetPreview() },
	)
	av.AddWidget2(d.assetTable.QWidget, 1)

	d.assetPreview = qt.NewQLabel2()
	d.assetPreview.SetMinimumHeight(220)
	d.assetPreview.SetAlignment(qt.AlignCenter)
	d.assetPreview.SetText("select an image to preview")
	av.AddWidget(d.assetPreview.QWidget)
	return assets
}

func (d *scrapeDialog) start() {
	// A single target is editable in the window; a CIDR block is not a scrape
	// target, so it is rejected rather than silently mangled.
	if d.targetEdit != nil {
		raw := strings.TrimSpace(d.targetEdit.Text())
		if raw == "" {
			d.u.status.ShowMessage("enter a target to scrape")
			return
		}
		if _, _, ok := parseBlockTarget(raw); ok {
			d.u.status.ShowMessage("scrape works on a host or URL, not a CIDR block")
			return
		}
		d.targets = []ScrapeTarget{{Label: raw, URL: raw}}
	}
	if len(d.targets) == 0 {
		d.u.status.ShowMessage("no targets to scrape")
		return
	}

	scheme := d.scheme.CurrentText()
	port := d.port.Value()
	var targets []ScrapeTarget
	if d.targetEdit != nil {
		raw := strings.TrimSpace(d.targetEdit.Text())
		composed := composeScrapeURL(raw, scheme, port)
		if composed == "" {
			d.u.status.ShowMessage("enter a target to scrape")
			return
		}
		targets = []ScrapeTarget{{Label: raw, URL: composed}}
	} else {
		targets = make([]ScrapeTarget, 0, len(d.targets))
		for _, t := range d.targets {
			u := t.URL
			// A target that already carries a URL (a port-scan web service)
			// keeps its own scheme and port.
			if !strings.Contains(u, "://") {
				u = composeScrapeURL(u, scheme, port)
			}
			targets = append(targets, ScrapeTarget{Label: t.Label, URL: u})
		}
	}

	keywords := splitKeywords(d.keywords.Text())
	match := "any"
	if d.requireAll.IsChecked() {
		match = "all"
	}
	d.filterActive = len(keywords) > 0
	if d.filterActive {
		msg := fmt.Sprintf("keyword filter: %s (match %s) — only matching pages are indexed",
			strings.Join(keywords, ", "), match)
		d.appendLog("info", msg)
		d.u.logLine("scrape", "info", msg)
		d.win.SetWindowTitle("Scrape · " + strings.Join(keywords, ", "))
	} else {
		d.appendLog("warn", "no keyword filter — every fetched page will be indexed")
		d.u.logLine("scrape", "warn", "no keyword filter — every fetched page will be indexed")
		d.win.SetWindowTitle("Scrape")
	}
	req := ScrapeRequest{
		Targets:         targets,
		Depth:           d.depth.Value(),
		Mode:            d.mode.CurrentText(),
		Scope:           scrapeScopeValue(d.scope.CurrentIndex()),
		Keywords:        keywords,
		KeywordMatch:    match,
		MaxPages:        d.maxPages.Value(),
		Concurrency:     d.concurrency.Value(),
		TimeoutMs:       d.timeout.Value(),
		IndexTest:       d.indexTest.IsChecked(),
		DelaySeconds:    d.delaySec.Value(),
		DelayEvery:      d.delayEvery.Value(),
		UserAgent:       d.selectedUserAgent(),
		IgnoreTLSErrors: d.ignoreTLS.IsChecked(),
	}

	d.pages = nil
	d.assets = nil
	d.leaks = nil
	d.renderPages()
	d.renderAssets()
	d.renderLeaks()
	d.log.Clear()
	d.startedAt = time.Now()
	d.jobID = 0
	d.startB.SetEnabled(false)
	d.cancelB.SetEnabled(true)
	d.u.startOp("scrape")
	d.u.openChannel("scrape")
	d.u.startActivity(fmt.Sprintf("scrape %d target(s) · depth %d · %s", len(d.targets), req.Depth, req.Mode), []activityStep{
		{Label: "fetch pages", Enabled: true},
		{Label: "download media (" + req.Mode + ")", Enabled: req.Mode != "html"},
		{Label: "store & index", Enabled: true},
		{Label: "keyword filter " + strings.Join(keywords, ", "), Enabled: len(keywords) > 0},
	})
	go func() {
		if err := d.u.app.Scrape(req); err != nil {
			d.appendLog("error", err.Error())
		}
	}()
}

func (d *scrapeDialog) finish(status string) {
	d.startB.SetEnabled(true)
	d.cancelB.SetEnabled(false)
	d.u.finishOp()
	d.appendLog("ok", fmt.Sprintf("finished (%s) · %d pages, %d assets", status, len(d.pages), len(d.assets)))
}

func (d *scrapeDialog) export() {
	targets := make([]string, 0, len(d.targets))
	for _, t := range d.targets {
		targets = append(targets, t.URL)
	}
	report := ScrapeReport{
		Label:        d.targetsLabel(),
		Targets:      targets,
		Depth:        d.depth.Value(),
		Mode:         d.mode.CurrentText(),
		Scope:        scrapeScopeValue(d.scope.CurrentIndex()),
		Keywords:     splitKeywords(d.keywords.Text()),
		KeywordMatch: map[bool]string{true: "all", false: "any"}[d.requireAll.IsChecked()],
		Status:       "reported",
		StartedAt:    d.startedAt.UnixMilli(),
		UserAgent:    d.userAgentLabel(),
		DelaySeconds: d.delaySec.Value(),
		DelayEvery:   d.delayEvery.Value(),
		IgnoreTLS:    d.ignoreTLS.IsChecked(),
		Pages:        len(d.pages),
		Assets:       len(d.assets),
		Leaks:        len(d.leaks),
	}
	if !d.startedAt.IsZero() {
		report.DurationMs = time.Since(d.startedAt).Milliseconds()
	}
	if _, err := d.u.app.ExportScrapeReport(report); err != nil {
		d.u.status.ShowMessage(err.Error())
	}
}

func (d *scrapeDialog) targetsLabel() string {
	if len(d.targets) == 0 {
		return "scrape"
	}
	label := d.targets[0].Label
	if label == "" {
		label = d.targets[0].URL
	}
	if len(d.targets) > 1 {
		label = fmt.Sprintf("%s (+%d)", label, len(d.targets)-1)
	}
	return label
}

// selectedUserAgent returns the User-Agent string for the current selection.
func (d *scrapeDialog) selectedUserAgent() string {
	i := d.userAgent.CurrentIndex()
	if i >= 0 && i < len(scrapeUserAgents) {
		return scrapeUserAgents[i].Value
	}
	return ""
}

// userAgentLabel returns the dropdown label for the report.
func (d *scrapeDialog) userAgentLabel() string {
	if d.userAgent == nil {
		return ""
	}
	return d.userAgent.CurrentText()
}

func (d *scrapeDialog) openArchiveFolder() {
	dir := d.u.app.ScrapeArchiveDir()
	if dir == "" {
		d.u.status.ShowMessage("no archive directory")
		return
	}
	qt.QDesktopServices_OpenUrl(qt.QUrl_FromLocalFile(dir))
}

func (d *scrapeDialog) renderPages() {
	fillScrapePageTable(d.pageTable, d.pages)
}

func (d *scrapeDialog) renderAssets() {
	fillScrapeAssetTable(d.assetTable, d.assets, d.assetKind.CurrentText())
}

func (d *scrapeDialog) renderLeaks() {
	fillScrapeLeakTable(d.leakTable, d.leaks)
}

func (d *scrapeDialog) leakMenu(pos *qt.QPoint) {
	item := d.leakTable.ItemAt(pos)
	if item == nil {
		return
	}
	d.leakTable.SetCurrentItem(item)
	if l, ok := scrapeLeakAt(d.leakTable, d.leaks); ok {
		scrapeLeakMenu(d.leakTable, pos, l)
	}
}

func (d *scrapeDialog) openSelectedLeak() {
	if l, ok := scrapeLeakAt(d.leakTable, d.leaks); ok {
		qt.QDesktopServices_OpenUrl(qt.NewQUrl3(l.URL))
	}
}

func (d *scrapeDialog) selectedPage() (scrape.PageSummary, bool) {
	return scrapePageAt(d.pageTable, d.pages)
}

func (d *scrapeDialog) selectedAsset() (scrape.AssetSummary, bool) {
	return scrapeAssetAt(d.assetTable, d.assets)
}

func (d *scrapeDialog) pageMenu(pos *qt.QPoint) {
	item := d.pageTable.ItemAt(pos)
	if item == nil {
		return
	}
	d.pageTable.SetCurrentItem(item)
	p, ok := d.selectedPage()
	if !ok {
		return
	}
	scrapePageMenu(d.u, d.win.QWidget, d.pageTable, pos, p)
}

func (d *scrapeDialog) assetMenu(pos *qt.QPoint) {
	item := d.assetTable.ItemAt(pos)
	if item == nil {
		return
	}
	d.assetTable.SetCurrentItem(item)
	a, ok := d.selectedAsset()
	if !ok {
		return
	}
	scrapeAssetMenu(d.u, d.win.QWidget, d.assetTable, pos, a)
}

func (d *scrapeDialog) previewSelectedPage() {
	if p, ok := d.selectedPage(); ok {
		d.u.previewScrapePage(d.win.QWidget, p.ID)
	}
}

func (d *scrapeDialog) openSelectedAsset() {
	if a, ok := d.selectedAsset(); ok {
		d.u.openScrapeAssetFile(a.ID)
	}
}

func (d *scrapeDialog) updateAssetPreview() {
	a, ok := d.selectedAsset()
	if !ok {
		d.assetPreview.SetPixmap(qt.NewQPixmap())
		d.assetPreview.SetText("select an image to preview")
		return
	}
	d.u.previewScrapeAsset(d.assetPreview, a)
}

func (d *scrapeDialog) appendLog(level, message string) {
	if d.log == nil {
		return
	}
	d.log.AppendPlainText(fmt.Sprintf("%s  %-5s %s", time.Now().Format("15:04:05"), strings.ToUpper(level), message))
}

// ---- event sinks (called on the Qt thread) ----

func (d *scrapeDialog) onPage(e ScrapePageEvent) {
	// Defensive: while a keyword filter is active, never show a page that the
	// filter did not index (its Matched list would be empty).
	if d.filterActive && len(e.Matched) == 0 {
		return
	}
	if e.JobID != 0 {
		d.jobID = e.JobID
	}
	d.pages = append(d.pages, scrape.PageSummary{
		ID: e.ID, JobID: e.JobID, URL: e.URL, Title: e.Title,
		Status: e.Status, Depth: e.Depth, Size: e.Size, Matched: e.Matched,
	})
	d.renderPages()
	line := fmt.Sprintf("%d %s", e.Status, e.URL)
	if len(e.Matched) > 0 {
		line += " · " + strings.Join(e.Matched, ",")
	}
	d.appendLog("ok", line)
}

func (d *scrapeDialog) onAsset(e ScrapeAssetEvent) {
	d.assets = append(d.assets, scrape.AssetSummary{
		ID: e.ID, JobID: e.JobID, URL: e.URL, Filename: e.Filename,
		Ext: e.Ext, MIME: e.MIME, Kind: e.Kind, Size: e.Size,
	})
	d.renderAssets()
	d.appendLog("info", fmt.Sprintf("asset %s (%s)", e.URL, e.Kind))
}

func (d *scrapeDialog) onLeak(e ScrapeLeakEvent) {
	d.leaks = append(d.leaks, scrape.LeakSummary{
		ID: e.ID, JobID: e.JobID, URL: e.URL, Status: e.Status,
		Kind: e.Kind, Title: e.Title, Entries: e.Entries,
	})
	d.renderLeaks()
	d.appendLog("ok", fmt.Sprintf("DIR LISTING %s (%d entries)", e.URL, e.Entries))
}

func (d *scrapeDialog) onDone(e ScrapeDoneEvent) {
	if e.JobID != 0 {
		d.jobID = e.JobID
	}
	d.finish(e.Status)
}

func (u *uiApp) onScrapePage(e ScrapePageEvent) {
	if u.scrapeDlg != nil {
		u.scrapeDlg.onPage(e)
	}
	line := fmt.Sprintf("%d %s", e.Status, e.URL)
	if len(e.Matched) > 0 {
		line += " · " + strings.Join(e.Matched, ",")
	}
	u.logLine("scrape", "ok", line)
}

func (u *uiApp) onScrapeAsset(e ScrapeAssetEvent) {
	if u.scrapeDlg != nil {
		u.scrapeDlg.onAsset(e)
	}
	u.logLine("scrape", "info", fmt.Sprintf("asset %s (%s)", e.URL, e.Kind))
}

func (u *uiApp) onScrapeLeak(e ScrapeLeakEvent) {
	if u.scrapeDlg != nil {
		u.scrapeDlg.onLeak(e)
	}
	u.logLine("scrape", "warn", fmt.Sprintf("DIR LISTING %s (%d entries)", e.URL, e.Entries))
}

// splitKeywords parses a comma or newline separated keyword list.
func splitKeywords(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func scrapeScopeValue(index int) string {
	if index == 1 {
		return "site"
	}
	return "host"
}

// scrapeSchemeTexts is the scheme selector, in combo order.
var scrapeSchemeTexts = []string{"http://", "https://", "http://www.", "https://www."}

// scrapeTargetSpec is a target decomposed into the run window's fields.
type scrapeTargetSpec struct {
	HostPath string // host [+ path], no scheme, no port, no www
	Scheme   string // a scrapeSchemeTexts entry
	Port     int    // 0 = the scheme's default port
}

// parseScrapeTarget splits a raw target into host, path, scheme and port so the
// run window can pre-fill its fields — a port-scan web service arrives as a
// full URL like https://host:8443/.
func parseScrapeTarget(raw string) scrapeTargetSpec {
	spec := scrapeTargetSpec{Scheme: "http://"}
	raw = strings.TrimSpace(raw)
	scheme := "http"
	if i := strings.Index(raw, "://"); i >= 0 {
		if strings.EqualFold(raw[:i], "https") {
			scheme = "https"
		}
		raw = raw[i+3:]
	}
	authority, rest := raw, ""
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		authority, rest = raw[:i], raw[i:]
	}
	host, port := authority, 0
	if h, p, err := net.SplitHostPort(authority); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	} else {
		host = strings.Trim(authority, "[]")
	}
	www := strings.HasPrefix(strings.ToLower(host), "www.")
	if www {
		host = host[4:]
	}
	if rest == "/" {
		rest = ""
	}
	spec.HostPath = host + rest
	spec.Port = port
	spec.Scheme = schemeTextFor(scheme, www)
	return spec
}

func schemeTextFor(scheme string, www bool) string {
	switch {
	case scheme == "https" && www:
		return "https://www."
	case scheme == "http" && www:
		return "http://www."
	case scheme == "https":
		return "https://"
	default:
		return "http://"
	}
}

func schemeTextIndex(text string) int {
	for i, s := range scrapeSchemeTexts {
		if s == text {
			return i
		}
	}
	return 0
}

// commonSchemeText returns the shared scheme text when every spec agrees.
func commonSchemeText(specs []scrapeTargetSpec) (string, bool) {
	if len(specs) == 0 {
		return "", false
	}
	first := specs[0].Scheme
	for _, s := range specs[1:] {
		if s.Scheme != first {
			return "", false
		}
	}
	return first, true
}

// commonPort returns the shared port when every spec agrees on a non-zero one.
func commonPort(specs []scrapeTargetSpec) int {
	if len(specs) == 0 {
		return 0
	}
	first := specs[0].Port
	if first == 0 {
		return 0
	}
	for _, s := range specs[1:] {
		if s.Port != first {
			return 0
		}
	}
	return first
}

// composeScrapeURL builds a final URL from the run window's host, scheme and
// port fields. A host that already carries a scheme is treated as a full URL;
// an empty port leaves the URL on the scheme's default port.
func composeScrapeURL(host, schemeText string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	scheme, www := splitSchemeText(schemeText)

	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return host
		}
		if port > 0 && u.Port() == "" {
			u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
		}
		return u.String()
	}

	authority, rest := host, ""
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		authority, rest = host[:i], host[i:]
	}
	h := authority
	if _, _, err := net.SplitHostPort(authority); err == nil {
		// The host text already names a port; it wins over the field.
	} else if port > 0 {
		h = net.JoinHostPort(strings.Trim(authority, "[]"), strconv.Itoa(port))
	}
	if www {
		hostname, portSuffix := h, ""
		if hn, p, err := net.SplitHostPort(h); err == nil {
			hostname, portSuffix = hn, ":"+p
		}
		if net.ParseIP(strings.Trim(hostname, "[]")) == nil && !strings.HasPrefix(strings.ToLower(hostname), "www.") {
			h = "www." + hostname + portSuffix
		}
	}
	return scheme + "://" + h + rest
}

func splitSchemeText(schemeText string) (scheme string, www bool) {
	switch schemeText {
	case "https://":
		return "https", false
	case "http://www.":
		return "http", true
	case "https://www.":
		return "https", true
	default:
		return "http", false
	}
}

// scrapeSearchField maps the search field selector to the store's field name.
func scrapeSearchField(index int) string {
	switch index {
	case 1:
		return "title"
	case 2:
		return "meta"
	case 3:
		return "url"
	case 4:
		return "text"
	case 5:
		return "html"
	case 6:
		return "filename"
	default:
		return "all"
	}
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---- shared table / menu / preview helpers ----

// scrapeAssetKinds is the asset-kind filter list, shared by both windows.
func scrapeAssetKinds() []string {
	return []string{"all", "image", "video", "audio", "stylesheet", "script", "font", "document", "other"}
}

func newScrapePageTable(menu func(*qt.QPoint), open func()) *qt.QTreeWidget {
	tree := qt.NewQTreeWidget2()
	tree.SetColumnCount(6)
	tree.SetHeaderLabels([]string{"URL", "Status", "Depth", "Title", "Size", "Matched"})
	tree.SetSelectionMode(qt.QAbstractItemView__ExtendedSelection)
	tree.SetContextMenuPolicy(qt.CustomContextMenu)
	tree.OnCustomContextMenuRequested(menu)
	tree.OnItemDoubleClicked(func(item *qt.QTreeWidgetItem, col int) { open() })
	return tree
}

func newScrapeAssetTable(menu func(*qt.QPoint), open func(), selectChanged func()) *qt.QTreeWidget {
	tree := qt.NewQTreeWidget2()
	tree.SetColumnCount(5)
	tree.SetHeaderLabels([]string{"Kind", "Filename", "MIME", "Size", "URL"})
	tree.SetContextMenuPolicy(qt.CustomContextMenu)
	tree.OnCustomContextMenuRequested(menu)
	tree.OnItemDoubleClicked(func(item *qt.QTreeWidgetItem, col int) { open() })
	tree.OnItemSelectionChanged(selectChanged)
	return tree
}

// maxScrapeListRows bounds how many rows the live Pages table renders, so a
// large crawl cannot balloon the UI. Every indexed page is still stored and
// reachable through Browse index / Search; only the live table is capped.
const maxScrapeListRows = 2000

func fillScrapePageTable(tree *qt.QTreeWidget, pages []scrape.PageSummary) {
	tree.Clear()
	shown := pages
	if len(shown) > maxScrapeListRows {
		shown = shown[:maxScrapeListRows]
		tree.SetToolTip(fmt.Sprintf("showing first %d of %d indexed pages — use Browse index / Search for the rest", len(shown), len(pages)))
	} else {
		tree.SetToolTip("")
	}
	for _, p := range shown {
		item := qt.NewQTreeWidgetItem3(tree)
		item.SetText(0, p.URL)
		item.SetText(1, fmt.Sprintf("%d", p.Status))
		item.SetText(2, fmt.Sprintf("%d", p.Depth))
		item.SetText(3, p.Title)
		item.SetText(4, formatBytes(int64(p.Size)))
		item.SetText(5, strings.Join(p.Matched, ", "))
	}
}

func newScrapeLeakTable(menu func(*qt.QPoint), open func()) *qt.QTreeWidget {
	tree := qt.NewQTreeWidget2()
	tree.SetColumnCount(5)
	tree.SetHeaderLabels([]string{"URL", "Status", "Entries", "Kind", "Title"})
	tree.SetContextMenuPolicy(qt.CustomContextMenu)
	tree.OnCustomContextMenuRequested(menu)
	tree.OnItemDoubleClicked(func(item *qt.QTreeWidgetItem, col int) { open() })
	return tree
}

func fillScrapeLeakTable(tree *qt.QTreeWidget, leaks []scrape.LeakSummary) {
	tree.Clear()
	for _, l := range leaks {
		item := qt.NewQTreeWidgetItem3(tree)
		item.SetText(0, l.URL)
		item.SetText(1, fmt.Sprintf("%d", l.Status))
		item.SetText(2, fmt.Sprintf("%d", l.Entries))
		item.SetText(3, l.Kind)
		item.SetText(4, l.Title)
	}
}

func scrapeLeakAt(tree *qt.QTreeWidget, leaks []scrape.LeakSummary) (scrape.LeakSummary, bool) {
	item := tree.CurrentItem()
	if item == nil {
		return scrape.LeakSummary{}, false
	}
	idx := tree.IndexOfTopLevelItem(item)
	if idx < 0 || idx >= len(leaks) {
		return scrape.LeakSummary{}, false
	}
	return leaks[idx], true
}

func scrapeLeakMenu(tree *qt.QTreeWidget, pos *qt.QPoint, l scrape.LeakSummary) {
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Open in browser", func() { qt.QDesktopServices_OpenUrl(qt.NewQUrl3(l.URL)) })
	addMenuAction(menu, "Copy URL", func() { qt.QGuiApplication_Clipboard().SetText(l.URL) })
	execScrapeMenu(menu, tree, pos)
}

func fillScrapeAssetTable(tree *qt.QTreeWidget, assets []scrape.AssetSummary, kind string) {
	tree.Clear()
	for _, a := range assets {
		if kind != "all" && kind != "" && a.Kind != kind {
			continue
		}
		item := qt.NewQTreeWidgetItem3(tree)
		item.SetText(0, a.Kind)
		item.SetText(1, a.Filename)
		item.SetText(2, a.MIME)
		item.SetText(3, formatBytes(a.Size))
		item.SetText(4, a.URL)
	}
}

func scrapePageAt(tree *qt.QTreeWidget, pages []scrape.PageSummary) (scrape.PageSummary, bool) {
	item := tree.CurrentItem()
	if item == nil {
		return scrape.PageSummary{}, false
	}
	idx := tree.IndexOfTopLevelItem(item)
	if idx < 0 || idx >= len(pages) {
		return scrape.PageSummary{}, false
	}
	return pages[idx], true
}

func scrapeAssetAt(tree *qt.QTreeWidget, assets []scrape.AssetSummary) (scrape.AssetSummary, bool) {
	item := tree.CurrentItem()
	if item == nil {
		return scrape.AssetSummary{}, false
	}
	idx := tree.IndexOfTopLevelItem(item)
	if idx < 0 || idx >= len(assets) {
		return scrape.AssetSummary{}, false
	}
	return assets[idx], true
}

// scrapePageMenu is the shared context menu for a page row.
func scrapePageMenu(u *uiApp, parent *qt.QWidget, tree *qt.QTreeWidget, pos *qt.QPoint, p scrape.PageSummary) {
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Preview", func() { u.previewScrapePage(parent, p.ID) })
	addMenuAction(menu, "Open in browser", func() { qt.QDesktopServices_OpenUrl(qt.NewQUrl3(p.URL)) })
	addMenuAction(menu, "View raw HTML", func() { u.viewScrapeHTML(parent, p.ID) })
	addMenuAction(menu, "Copy URL", func() { qt.QGuiApplication_Clipboard().SetText(p.URL) })
	execScrapeMenu(menu, tree, pos)
}

// scrapeAssetMenu is the shared context menu for an asset row.
func scrapeAssetMenu(u *uiApp, parent *qt.QWidget, tree *qt.QTreeWidget, pos *qt.QPoint, a scrape.AssetSummary) {
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Open", func() { u.openScrapeAssetFile(a.ID) })
	addMenuAction(menu, "Reveal in file manager", func() { u.revealScrapeAsset(a.ID) })
	addMenuAction(menu, "Open in browser", func() { qt.QDesktopServices_OpenUrl(qt.NewQUrl3(a.URL)) })
	addMenuAction(menu, "Copy URL", func() { qt.QGuiApplication_Clipboard().SetText(a.URL) })
	execScrapeMenu(menu, tree, pos)
}

func execScrapeMenu(menu *qt.QMenu, tree *qt.QTreeWidget, pos *qt.QPoint) {
	gp := tree.MapToGlobal(qt.NewQPointF3(float64(pos.X()), float64(pos.Y())))
	menu.ExecWithPos(qt.NewQPoint2(int(gp.X()), int(gp.Y())))
}

// previewScrapePage shows a stored document's text in a dialog.
func (u *uiApp) previewScrapePage(parent *qt.QWidget, id int64) {
	page, err := u.app.LoadScrapePage(id)
	if err != nil {
		u.status.ShowMessage(err.Error())
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", page.Title)
	fmt.Fprintf(&b, "%s\n", page.URL)
	if page.FinalURL != "" && page.FinalURL != page.URL {
		fmt.Fprintf(&b, "→ %s\n", page.FinalURL)
	}
	if page.Canonical != "" {
		fmt.Fprintf(&b, "canonical: %s\n", page.Canonical)
	}
	if len(page.Keywords) > 0 {
		fmt.Fprintf(&b, "matched: %s\n", strings.Join(page.Keywords, ", "))
	}
	b.WriteString("\n")
	if page.Meta != "" {
		b.WriteString(page.Meta)
		b.WriteString("\n")
	}
	b.WriteString(page.Text)
	dlg, tb := textDialog(parent, "Page preview", 900, 700)
	tb.SetPlainText(b.String())
	dlg.Show()
	dlg.Raise()
}

// viewScrapeHTML shows a stored document's raw HTML (unrendered).
func (u *uiApp) viewScrapeHTML(parent *qt.QWidget, id int64) {
	page, err := u.app.LoadScrapePage(id)
	if err != nil {
		u.status.ShowMessage(err.Error())
		return
	}
	dlg, tb := textDialog(parent, "Raw HTML (not rendered)", 900, 700)
	tb.SetPlainText(page.HTML)
	dlg.Show()
	dlg.Raise()
}

// openScrapeAssetFile opens a stored asset with the platform handler.
func (u *uiApp) openScrapeAssetFile(id int64) {
	path, err := u.app.OpenScrapeAsset(id)
	if err != nil {
		u.status.ShowMessage(err.Error())
		return
	}
	if path == "" {
		u.status.ShowMessage("asset has no stored body")
		return
	}
	qt.QDesktopServices_OpenUrl(qt.QUrl_FromLocalFile(path))
}

// revealScrapeAsset opens the asset's containing directory.
func (u *uiApp) revealScrapeAsset(id int64) {
	path, err := u.app.OpenScrapeAsset(id)
	if err != nil || path == "" {
		u.status.ShowMessage("asset has no stored body")
		return
	}
	qt.QDesktopServices_OpenUrl(qt.QUrl_FromLocalFile(filepath.Dir(path)))
}

// previewScrapeAsset renders an image asset into a label, or a message for
// non-images.
func (u *uiApp) previewScrapeAsset(label *qt.QLabel, a scrape.AssetSummary) {
	if a.Kind != "image" {
		label.SetPixmap(qt.NewQPixmap())
		label.SetText(a.Kind + " · " + a.Filename)
		return
	}
	path, err := u.app.OpenScrapeAsset(a.ID)
	if err != nil || path == "" {
		label.SetText("no preview")
		return
	}
	px := qt.NewQPixmap4(path)
	if px.IsNull() {
		label.SetText("no preview")
		return
	}
	w, h := label.Width(), label.Height()
	if w < 80 {
		w = 640
	}
	if h < 80 {
		h = 360
	}
	label.SetText("")
	label.SetPixmap(px.Scaled(w, h))
}

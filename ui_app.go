package main

import (
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"

	"traceroute/internal/dnscheck"
	"traceroute/internal/geolocator"
	"traceroute/internal/httpcheck"
	"traceroute/internal/mapdata"
	"traceroute/internal/mapview"
	"traceroute/internal/subdomains"
	"traceroute/internal/webcrawl"
)

// mapHit is the metadata attached to every map marker.
type mapHit struct {
	Trace int
	Hop   int
	IP    string
	Label string
	Count int
}

// origins are confirmed/likely origins discovered by "Unmask target".
type originMarker struct {
	IP      string
	Lat     float64
	Lon     float64
	Verdict string
	Label   string
}

// uiApp is the Qt front-end controller.
type uiApp struct {
	app   *App
	world *mapdata.World

	win    *qt.QMainWindow
	status *qt.QStatusBar

	root           *qt.QWidget
	target         *qt.QLineEdit
	badge          *qt.QLabel
	maxHops        *qt.QSpinBox
	traceB         *qt.QPushButton
	scanB          *qt.QPushButton
	portsB         *qt.QPushButton
	cancelB        *qt.QPushButton
	saveHistAction *qt.QAction
	corrAction     *qt.QAction
	motionAction   *qt.QAction
	unmaskAction   *qt.QAction

	statusStats *qt.QLabel
	statusOp    *qt.QLabel
	opTimer     *qt.QTimer
	opStarted   time.Time
	opLabel     string

	mapView      *mapview.MapView
	split        *qt.QSplitter
	leftBar      *qt.QWidget
	rightBar     *qt.QWidget
	rightVisible bool

	hopTree   *qt.QTreeWidget
	traceTree *qt.QTreeWidget
	subTree   *qt.QTreeWidget
	corrTree  *qt.QTreeWidget
	dnsTree   *qt.QTreeWidget

	targetsPane  *qt.QWidget
	targetsCount *qt.QLabel
	hopsPane     *qt.QWidget
	hopTitle     *qt.QLabel
	hopsCount    *qt.QLabel
	corrPane     *qt.QWidget
	corrCount    *qt.QLabel
	dnsPane      *qt.QWidget
	dnsCount     *qt.QLabel
	subsPane     *qt.QWidget
	subsCount    *qt.QLabel
	subTraceBtn  *qt.QPushButton
	subWait      *qt.QLabel

	traces           []*traceState
	hidden           map[int]bool
	populatingTraces bool
	focused          int
	selectedHop      int
	correlate        bool
	motion           bool
	origins          []originMarker
	sharedHops       map[string]int

	records     []dnsRecord
	lastTarget  []string
	lastMaxHops int
	scanTargets []PortScanTarget
	crawlPages  []webcrawl.Page
	subs        []subdomains.Result

	selectedSubs   map[string]bool
	tracingSubs    bool
	scanPhase      string
	scanDone       int
	scanTotal      int
	seenPhases     map[string]bool
	populatingSubs bool
	scanCompleted  bool
	dnsOpen        bool
	dnsToggle      *qt.QPushButton

	channels map[string]*logWindow
	logSeq   int

	portDlg        *portDialog
	domainDlg      *domainDialog
	originDlg      *originDialog
	endpointDlg    *endpointDialog
	geocacheDlg    *geocacheDialog
	ipblocksDlg    *ipblocksDialog
	historyDlg     *historyDialog
	scrapeDlg      *scrapeDialog
	scrapeIndexDlg *scrapeIndexDialog
	netcats        map[string]*netcatWindow
	netcatEOL      int
	popup          *qt.QWidget

	themeDark bool
}

// dnsRecord is a minimal mirror of dnscheck.Record for the DNS sidebar.
type dnsRecord struct {
	Type     string
	Name     string
	Value    string
	Priority int
}

func newUI(app *App, world *mapdata.World) *uiApp {
	u := &uiApp{
		app:          app,
		world:        world,
		hidden:       map[int]bool{},
		focused:      -1,
		lastMaxHops:  30,
		motion:       true,
		sharedHops:   map[string]int{},
		selectedSubs: map[string]bool{},
		seenPhases:   map[string]bool{},
		channels:     map[string]*logWindow{},
		themeDark:    true,
		dnsOpen:      true,
	}
	app.SetDialogs(qtDialogs{})
	app.SetEmitter(func(name string, payload any) {
		mainthread.Start(func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ui: event %q failed: %v", name, r)
				}
			}()
			u.handle(name, payload)
		})
	})
	u.build()
	return u
}

func (u *uiApp) build() {
	u.win = qt.NewQMainWindow2()
	u.win.SetWindowTitle("Traceroute Map")
	u.win.Resize(1280, 860)

	central := qt.NewQWidget2()
	vbox := qt.NewQVBoxLayout(central)
	vbox.SetContentsMargins(6, 6, 6, 6)
	vbox.SetSpacing(6)

	header := u.buildHeader()
	header.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	vbox.AddWidget(header)

	toolbar := u.buildToolbar()
	// The toolbar is a single fixed-height row; the splitter takes the rest.
	toolbar.SetSizePolicy2(qt.QSizePolicy__Preferred, qt.QSizePolicy__Fixed)
	vbox.AddWidget(toolbar)

	u.split = qt.NewQSplitter3(qt.Horizontal)
	u.split.AddWidget(u.buildLeftSidebar())
	u.mapView = mapview.New(u.world)
	u.mapView.SetMotion(u.motion)
	u.mapView.OnSelect(func(id string, meta any, gx, gy int) { u.onMarkerSelect(id, meta, gx, gy) })
	u.mapView.OnContext(func(id string, meta any, gx, gy int) { u.onMarkerContext(id, meta, gx, gy) })
	u.split.AddWidget(u.mapView.QWidget)
	u.rightBar = u.buildRightSidebar()
	u.rightBar.Hide()
	u.split.AddWidget(u.rightBar)
	u.split.SetStretchFactor(0, 0)
	u.split.SetStretchFactor(1, 1)
	u.split.SetStretchFactor(2, 0)
	vbox.AddWidget2(u.split.QWidget, 1)

	u.win.SetCentralWidget(central)
	u.status = qt.NewQStatusBar2()
	u.win.SetStatusBar(u.status)
	u.buildMenuBar()

	// Permanent status-bar readouts: the live elapsed timer on the right, then
	// the located/shared summary.
	u.statusOp = qt.NewQLabel2()
	u.statusOp.SetText("idle")
	u.statusStats = qt.NewQLabel2()
	u.statusStats.SetText("")
	u.status.AddPermanentWidget(u.statusStats.QWidget)
	u.status.AddPermanentWidget(u.statusOp.QWidget)

	u.opTimer = qt.NewQTimer2(u.win.QObject)
	u.opTimer.SetInterval(500)
	u.opTimer.OnTimeout(func() { u.updateElapsed() })
	u.opTimer.Stop()

	u.status.ShowMessage("Ready")
	u.refreshSidebar()
}

// buildHeader draws the app bar: the brand and the data-source meta line.
func (u *uiApp) buildHeader() *qt.QWidget {
	bar := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(bar)
	h.SetContentsMargins(2, 2, 2, 2)

	brand := qt.NewQLabel3("TRACEROUTE <span style='color:#2dd4ef'>/</span> NETWORK CONSOLE")
	bf := qt.NewQFont()
	bf.SetPointSize(12)
	bf.SetBold(true)
	brand.SetFont(bf)
	brand.SetTextFormat(qt.RichText)
	h.AddWidget(brand.QWidget)
	h.AddStretch()

	meta := qt.NewQLabel3(fmt.Sprintf("GEO · ipwho.is    DNS · A/AAAA/CNAME/MX/NS/SOA    HOPS · max %d", u.defaultMaxHops()))
	meta.SetFont(monoFont())
	h.AddWidget(meta.QWidget)
	return bar
}

// defaultMaxHops is the pre-toolbar max-hop value; 30 mirrors the old console.
func (u *uiApp) defaultMaxHops() int { return 30 }

func (u *uiApp) buildToolbar() *qt.QWidget {
	row := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(row)
	h.SetContentsMargins(0, 0, 0, 0)

	u.target = qt.NewQLineEdit2()
	u.target.SetPlaceholderText("Hostname, IP, or CIDR (10.0.0.0/24:22,80)")
	u.target.SetMinimumWidth(320)
	u.target.OnReturnPressed(func() { u.startTrace() })
	u.target.OnTextChanged(func(string) { u.updateBadge() })
	h.AddWidget(u.target.QWidget)

	u.badge = qt.NewQLabel2()
	h.AddWidget(u.badge.QWidget)

	h.AddWidget(qt.NewQLabel3("MAX HOPS").QWidget)
	u.maxHops = qt.NewQSpinBox2()
	u.maxHops.SetRange(1, 100)
	u.maxHops.SetValue(u.defaultMaxHops())
	u.maxHops.SetSuffix("")
	h.AddWidget(u.maxHops.QWidget)

	u.traceB = newButton("Trace", func() { u.startTrace() })
	u.scanB = newButton("Scan", func() { u.openScanDialog() })
	u.portsB = newButton("Ports", func() { u.openPortScanDialog() })
	u.cancelB = newButton("Cancel", func() { u.cancel() })
	u.cancelB.SetEnabled(false)
	h.AddWidget(u.traceB.QWidget)
	h.AddWidget(u.scanB.QWidget)
	h.AddWidget(u.portsB.QWidget)
	h.AddWidget(u.cancelB.QWidget)

	clean := newButton("Clean", func() { u.clean() })
	h.AddWidget(clean.QWidget)

	h.AddStretch()

	return row
}

// buildMenuBar creates the main-window menu bar. The non-urgent actions that
// used to crowd the toolbar (history, correlate/motion, tools, window list)
// live here; the toolbar keeps only the target controls and Trace/Scan/Ports/
// Cancel/Clean.
func (u *uiApp) buildMenuBar() {
	bar := u.win.MenuBar()

	file := bar.AddMenuWithTitle("&File")
	u.saveHistAction = addMenuAction(file, "Add results to history", func() { u.saveHistory() })
	u.saveHistAction.SetEnabled(false)
	addMenuAction(file, "Browse history…", func() { u.openHistoryDialog() })
	file.AddSeparator()
	addMenuAction(file, "Clean state", func() { u.clean() })

	view := bar.AddMenuWithTitle("&View")
	u.corrAction = addMenuAction(view, "Correlate", func() { u.setCorrelate(!u.correlate) })
	u.corrAction.SetCheckable(true)
	u.motionAction = addMenuAction(view, "Motion", func() { u.setMotion(!u.motion) })
	u.motionAction.SetCheckable(true)
	u.motionAction.SetChecked(u.motion)
	view.AddSeparator()
	addMenuAction(view, "Toggle theme", func() { u.toggleTheme() })

	tools := bar.AddMenuWithTitle("&Tools")
	u.unmaskAction = addMenuAction(tools, "Unmask target", func() { u.openOriginDialog() })
	u.unmaskAction.SetEnabled(false)
	addMenuAction(tools, "Domain analysis", func() { u.openDomainDialog() })
	addMenuAction(tools, "Port scan", func() { u.openPortScanDialog() })
	addMenuAction(tools, "Endpoint analysis", func() { u.openEndpointDialog() })
	scrapeMenu := tools.AddMenuWithTitle("Scrape")
	addMenuAction(scrapeMenu, "Scrape address…", func() { u.openScrapeAddress() })
	addMenuAction(scrapeMenu, "Scrape scan targets…", func() { u.openScrapeScanTargets() })
	scrapeMenu.AddSeparator()
	addMenuAction(scrapeMenu, "Browse index…", func() { u.openScrapeIndex() })
	addMenuAction(tools, "Netcat", func() { u.openNetcat() })
	addMenuAction(tools, "Netcat cheatsheets", func() { u.openCheatsheet("") })
	addMenuAction(tools, "GeoIP cache", func() { u.openGeoCacheDialog() })
	addMenuAction(tools, "Country IP blocks", func() { u.openIPBlocksDialog() })

	windows := bar.AddMenuWithTitle("&Windows")
	u.buildWindowsMenu(windows)

	help := bar.AddMenuWithTitle("&Help")
	addMenuAction(help, "About "+appName, func() { u.openAbout() })
	addMenuAction(help, "Licenses & notices", func() { u.openNotices() })
	addMenuAction(help, "About Qt", func() { qt.QMessageBox_AboutQt2(u.win.QWidget, "About Qt") })
}

// logChannels lists the docked console channels in Windows-menu order. The
// first entries get Ctrl+1..9 accelerators.
var logChannels = []struct{ kind, title string }{
	{"activity", "Activity"},
	{"console", "Console"},
	{"trace", "Trace log"},
	{"dns", "DNS records"},
	{"subdomains", "Subdomains"},
	{"crawl", "Crawl"},
	{"ports", "Ports"},
	{"origin", "Origin"},
	{"netcat", "Netcat"},
	{"scrape", "Scrape"},
}

// buildWindowsMenu fills the Windows menu with quick access to the docked log
// channels and the tool windows, so a window that is hidden, closed or merely
// behind another can be summoned with two clicks (or Ctrl+1..8).
func (u *uiApp) buildWindowsMenu(menu *qt.QMenu) {
	for i, ch := range logChannels {
		ch := ch
		a := addMenuAction(menu, ch.title, func() { u.openChannel(ch.kind) })
		if i < 9 {
			a.SetShortcut(qt.NewQKeySequence2(fmt.Sprintf("Ctrl+%d", i+1)))
		}
	}

	menu.AddSeparator()
	addMenuAction(menu, "Scan options", func() { u.openScanDialog() })
	addMenuAction(menu, "Port scan", func() {
		if u.portDlg == nil || !raiseDialog(u.portDlg.win) {
			u.openPortScanDialog()
		}
	})
	addMenuAction(menu, "Domain analysis", func() {
		if u.domainDlg == nil || !raiseDialog(u.domainDlg.win) {
			u.openDomainDialog()
		}
	})
	addMenuAction(menu, "Unmask target", func() {
		if u.originDlg == nil || !raiseDialog(u.originDlg.win) {
			u.openOriginDialog()
		}
	})
	addMenuAction(menu, "Endpoint analysis", func() {
		if u.endpointDlg == nil || !raiseDialog(u.endpointDlg.win) {
			u.openEndpointDialog()
		}
	})
	scrapeMenu := menu.AddMenuWithTitle("Scrape")
	addMenuAction(scrapeMenu, "Scrape address…", func() {
		if u.scrapeDlg == nil || !raiseDialog(u.scrapeDlg.win) {
			u.openScrapeAddress()
		}
	})
	addMenuAction(scrapeMenu, "Scrape scan targets…", func() { u.openScrapeScanTargets() })
	scrapeMenu.AddSeparator()
	addMenuAction(scrapeMenu, "Browse index…", func() {
		if u.scrapeIndexDlg == nil || !raiseDialog(u.scrapeIndexDlg.win) {
			u.openScrapeIndex()
		}
	})
	addMenuAction(menu, "Netcat", func() { u.openNetcat() })
	addMenuAction(menu, "Netcat cheatsheets", func() { u.openCheatsheet("") })
	addMenuAction(menu, "GeoIP cache", func() {
		if u.geocacheDlg == nil || !raiseDialog(u.geocacheDlg.win) {
			u.openGeoCacheDialog()
		}
	})
	addMenuAction(menu, "Country IP blocks", func() {
		if u.ipblocksDlg == nil || !raiseDialog(u.ipblocksDlg.win) {
			u.openIPBlocksDialog()
		}
	})
	addMenuAction(menu, "History", func() {
		if u.historyDlg == nil || !raiseDialog(u.historyDlg.win) {
			u.openHistoryDialog()
		}
	})
}

// raiseDialog shows and raises an existing transient window, reporting whether
// it existed. Used by the Windows menu to re-focus an already-open tool.
func raiseDialog(win *qt.QDialog) bool {
	if win == nil {
		return false
	}
	win.Show()
	win.Raise()
	win.ActivateWindow()
	return true
}

// setMotion toggles the travelling route-marker animation.
func (u *uiApp) setMotion(on bool) {
	u.motion = on
	if u.motionAction != nil {
		u.motionAction.SetChecked(on)
	}
	if u.mapView != nil {
		u.mapView.SetMotion(on)
	}
}

// paneHead builds a small section header ("TITLE … count") and returns the
// header widget plus its count label so the caller can update it.
func paneHead(title string) (*qt.QWidget, *qt.QLabel) {
	head := qt.NewQWidget2()
	h := qt.NewQHBoxLayout(head)
	h.SetContentsMargins(0, 2, 0, 0)
	h.AddWidget(qt.NewQLabel3(title).QWidget)
	h.AddStretch()
	count := qt.NewQLabel2()
	h.AddWidget(count.QWidget)
	return head, count
}

// buildLeftSidebar is the targets / hops / correlation panel on the left.
func (u *uiApp) buildLeftSidebar() *qt.QWidget {
	side := qt.NewQWidget2()
	v := qt.NewQVBoxLayout(side)
	v.SetContentsMargins(0, 0, 0, 0)
	v.SetSpacing(4)

	// TARGETS (shown only when more than one trace exists).
	u.targetsPane = qt.NewQWidget2()
	tv := qt.NewQVBoxLayout(u.targetsPane)
	tv.SetContentsMargins(0, 0, 0, 0)
	tHead, tCount := paneHead("TARGETS")
	u.targetsCount = tCount
	tv.AddWidget(tHead)
	u.traceTree = qt.NewQTreeWidget2()
	u.traceTree.SetColumnCount(3)
	u.traceTree.SetHeaderLabels([]string{"Trace", "Target", "IP"})
	u.traceTree.OnItemClicked(func(item *qt.QTreeWidgetItem, col int) { u.traceClicked(item) })
	u.traceTree.OnItemChanged(func(item *qt.QTreeWidgetItem, col int) { u.traceItemChanged(item, col) })
	u.traceTree.SetContextMenuPolicy(qt.CustomContextMenu)
	u.traceTree.OnCustomContextMenuRequested(func(pos *qt.QPoint) { u.traceContext(pos) })
	tv.AddWidget(u.traceTree.QWidget)
	v.AddWidget(u.targetsPane)

	// HOPS (title follows the focused trace).
	u.hopsPane = qt.NewQWidget2()
	hv := qt.NewQVBoxLayout(u.hopsPane)
	hv.SetContentsMargins(0, 0, 0, 0)
	hHead := qt.NewQWidget2()
	hh := qt.NewQHBoxLayout(hHead)
	hh.SetContentsMargins(0, 2, 0, 0)
	u.hopTitle = qt.NewQLabel3("HOPS")
	hh.AddWidget(u.hopTitle.QWidget)
	hh.AddStretch()
	u.hopsCount = qt.NewQLabel2()
	hh.AddWidget(u.hopsCount.QWidget)
	hv.AddWidget(hHead)
	u.hopTree = qt.NewQTreeWidget2()
	u.hopTree.SetColumnCount(4)
	u.hopTree.SetHeaderLabels([]string{"#", "IP", "RTT", "Location"})
	u.hopTree.OnItemClicked(func(item *qt.QTreeWidgetItem, col int) { u.hopClicked(item) })
	u.hopTree.SetContextMenuPolicy(qt.CustomContextMenu)
	u.hopTree.OnCustomContextMenuRequested(func(pos *qt.QPoint) { u.hopContext(pos) })
	hv.AddWidget(u.hopTree.QWidget)
	v.AddWidget2(u.hopsPane, 1)

	// CORRELATION (replaces HOPS in correlate mode).
	u.corrPane = qt.NewQWidget2()
	cv := qt.NewQVBoxLayout(u.corrPane)
	cv.SetContentsMargins(0, 0, 0, 0)
	cHead, cCount := paneHead("CORRELATION")
	u.corrCount = cCount
	cv.AddWidget(cHead)
	u.corrTree = qt.NewQTreeWidget2()
	u.corrTree.SetColumnCount(3)
	u.corrTree.SetHeaderLabels([]string{"IP", "Visits", "Paths"})
	cv.AddWidget(u.corrTree.QWidget)
	u.corrPane.Hide()
	v.AddWidget2(u.corrPane, 1)

	side.SetMinimumWidth(230)
	return side
}

// buildRightSidebar is the DNS records + subdomains discovery panel on the
// right. It stays hidden until a scan produces records or subdomains.
func (u *uiApp) buildRightSidebar() *qt.QWidget {
	side := qt.NewQWidget2()
	v := qt.NewQVBoxLayout(side)
	v.SetContentsMargins(0, 0, 0, 0)
	v.SetSpacing(4)

	// DNS RECORDS (collapsible).
	u.dnsPane = qt.NewQWidget2()
	dv := qt.NewQVBoxLayout(u.dnsPane)
	dv.SetContentsMargins(0, 0, 0, 0)
	dnsHead := qt.NewQWidget2()
	dh := qt.NewQHBoxLayout(dnsHead)
	dh.SetContentsMargins(0, 2, 0, 0)
	u.dnsToggle = qt.NewQPushButton3("▾ DNS RECORDS")
	u.dnsToggle.SetFlat(true)
	u.dnsToggle.OnClicked(func() { u.toggleDNSPanel() })
	dh.AddWidget(u.dnsToggle.QWidget)
	dh.AddStretch()
	u.dnsCount = qt.NewQLabel2()
	dh.AddWidget(u.dnsCount.QWidget)
	dv.AddWidget(dnsHead)
	u.dnsTree = qt.NewQTreeWidget2()
	u.dnsTree.SetColumnCount(2)
	u.dnsTree.SetHeaderLabels([]string{"Type", "Value"})
	dv.AddWidget2(u.dnsTree.QWidget, 1)
	v.AddWidget(u.dnsPane)

	// SUBDOMAINS.
	u.subsPane = qt.NewQWidget2()
	sv := qt.NewQVBoxLayout(u.subsPane)
	sv.SetContentsMargins(0, 0, 0, 0)
	sHead, sCount := paneHead("SUBDOMAINS")
	u.subsCount = sCount
	sv.AddWidget(sHead)

	tools := qt.NewQWidget2()
	th := qt.NewQHBoxLayout(tools)
	th.SetContentsMargins(0, 0, 0, 0)
	th.SetSpacing(4)
	th.AddWidget(newButton("All", func() { u.selectAllSubs() }).QWidget)
	th.AddWidget(newButton("None", func() { u.clearSubs() }).QWidget)
	u.subTraceBtn = newButton("Trace 0", func() { u.traceSelectedSubs() })
	u.subTraceBtn.SetEnabled(false)
	th.AddWidget(u.subTraceBtn.QWidget)
	th.AddStretch()
	sv.AddWidget(tools)

	u.subTree = qt.NewQTreeWidget2()
	u.subTree.SetColumnCount(3)
	u.subTree.SetHeaderLabels([]string{"Subdomain", "IPs", "Source"})
	u.subTree.SetColumnWidth(0, 170)
	u.subTree.OnItemChanged(func(item *qt.QTreeWidgetItem, col int) { u.subItemChanged(item, col) })
	sv.AddWidget2(u.subTree.QWidget, 1)

	u.subWait = qt.NewQLabel3("")
	u.subWait.SetWordWrap(true)
	u.subWait.Hide()
	sv.AddWidget(u.subWait.QWidget)

	u.subsPane.Hide()
	v.AddWidget2(u.subsPane, 1)

	side.SetMinimumWidth(230)
	return side
}

func newButton(text string, fn func()) *qt.QPushButton {
	b := qt.NewQPushButton3(text)
	if fn != nil {
		b.OnClicked(fn)
	}
	return b
}

func addMenuAction(menu *qt.QMenu, text string, fn func()) *qt.QAction {
	a := menu.AddActionWithText(text)
	a.OnTriggered(fn)
	return a
}

// ---- actions ----

func (u *uiApp) startTrace() {
	target := strings.TrimSpace(u.target.Text())
	if target == "" {
		return
	}
	hops := u.maxHops.Value()
	u.lastMaxHops = hops
	if cidr, ports, ok := parseBlockTarget(target); ok {
		u.resetForOperation()
		u.startOp("block " + cidr)
		u.openChannel("trace")
		portsLabel := ""
		if strings.TrimSpace(ports) != "" {
			portsLabel = " · ports " + strings.TrimSpace(ports)
		}
		u.startActivity(fmt.Sprintf("block trace %s%s · max %d hops", cidr, portsLabel, hops), []activityStep{
			{Label: "discover live hosts", Enabled: true},
			{Label: "traceroute live hosts", Enabled: true},
			{Label: "geolocate hops", Enabled: true},
		})
		u.logLine("trace", "info", fmt.Sprintf("▶ block trace %s%s · max %d hops", cidr, portsLabel, hops))
		u.logLine("console", "info", fmt.Sprintf("▶ block trace %s%s", cidr, portsLabel))
		go func() {
			err := u.app.TraceBlock(TraceBlockRequest{CIDR: cidr, PortRange: ports, MaxHops: hops})
			u.afterOp(err)
		}()
		return
	}
	u.resetForOperation()
	u.startOp("trace " + target)
	u.openChannel("trace")
	u.startActivity(fmt.Sprintf("trace %s · max %d hops", target, hops), []activityStep{
		{Label: "resolve target", Enabled: true},
		{Label: "traceroute", Enabled: true},
		{Label: "geolocate hops", Enabled: true},
	})
	u.logLine("trace", "info", fmt.Sprintf("▶ trace %s · max %d hops", target, hops))
	u.logLine("console", "info", fmt.Sprintf("▶ trace %s · max %d hops", target, hops))
	go func() {
		err := u.app.Trace(TraceRequest{Target: target, MaxHops: hops})
		u.afterOp(err)
	}()
}

func (u *uiApp) afterOp(err error) {
	mainthread.Start(func() {
		u.finishOp()
		if err != nil {
			u.logLine("console", "error", err.Error())
		}
	})
}

// startOp marks the status bar busy and starts the elapsed-time ticker.
func (u *uiApp) startOp(label string) {
	u.opLabel = label
	u.opStarted = time.Now()
	u.cancelB.SetEnabled(true)
	if u.opTimer != nil {
		u.opTimer.Start(500)
	}
	u.updateElapsed()
}

// finishOp clears the busy state and stops the elapsed-time ticker.
func (u *uiApp) finishOp() {
	if u.opTimer != nil {
		u.opTimer.Stop()
	}
	u.opLabel = ""
	u.cancelB.SetEnabled(false)
	if u.statusOp != nil {
		u.statusOp.SetText("idle")
	}
}

// updateElapsed refreshes the transient operation/elapsed status readout.
func (u *uiApp) updateElapsed() {
	if u.statusOp == nil || u.opLabel == "" {
		return
	}
	u.statusOp.SetText(fmt.Sprintf("%s · %s", u.opLabel, time.Since(u.opStarted).Round(time.Second)))
}

// activityStep is one line in the Activity panel's run plan. An enabled step is
// scheduled to run; a disabled one is reported as "not selected" so the user can
// see at a glance what the operation is deliberately skipping.
type activityStep struct {
	Label   string
	Enabled bool
}

// startActivity clears the Activity panel and prints the run plan for the
// operation about to start. Every step is listed up front — including the ones
// that are not selected — so one panel answers "what is running, and what is
// not?". It docks and raises the panel so progress is never hidden behind a tab
// the user did not know to check.
func (u *uiApp) startActivity(title string, steps []activityStep) {
	u.seenPhases = map[string]bool{}
	u.openChannel("activity")
	u.ensureChannel("activity").clear()
	u.logLine("activity", "info", "▶ "+title)
	for _, s := range steps {
		if s.Enabled {
			u.logLine("activity", "info", "  · "+s.Label+" — scheduled")
		} else {
			u.logLine("activity", "info", "  – "+s.Label+" — not selected")
		}
	}
}

// activityf appends one progress line to the Activity panel.
func (u *uiApp) activityf(level, format string, args ...any) {
	u.logLine("activity", level, fmt.Sprintf(format, args...))
}

// activityPhase opens a phase's section in the Activity panel the first time it
// is seen for the current operation, so a running scan shows which phase is
// active without repeating every progress tick.
func (u *uiApp) activityPhase(phase string) {
	if u.seenPhases[phase] {
		return
	}
	u.seenPhases[phase] = true
	u.activityf("info", "  ▸ %s …", activityPhaseLabel(phase))
}

// activityPhaseLabel maps a backend scan phase to a human label shared by the
// run plan and the phase lines.
func activityPhaseLabel(phase string) string {
	switch phase {
	case "subdomains":
		return "subdomain brute force"
	case "ptr":
		return "reverse DNS (PTR)"
	case "sweep":
		return "/24 reverse sweep"
	case "services":
		return "services (SPF/DMARC/SRV)"
	case "crawl":
		return "crawl pages & sitemaps"
	case "discover":
		return "discovering live hosts"
	case "dns":
		return "dns records"
	default:
		return phase
	}
}

func (u *uiApp) cancel() {
	u.app.Cancel()
	u.finishOp()
	u.status.ShowMessage("Cancelled")
}

func (u *uiApp) resetForOperation() {
	u.traces = nil
	u.hidden = map[int]bool{}
	u.focused = -1
	u.selectedHop = -1
	u.sharedHops = map[string]int{}
	u.records = nil
	u.subs = nil
	u.origins = nil
	u.scanTargets = nil
	u.crawlPages = nil
	u.selectedSubs = map[string]bool{}
	u.tracingSubs = false
	u.scanPhase = ""
	u.scanDone = 0
	u.scanTotal = 0
	u.correlate = false
	if u.corrAction != nil {
		u.corrAction.SetChecked(false)
	}
	u.scanCompleted = false
	if u.unmaskAction != nil {
		u.unmaskAction.SetEnabled(false)
	}
	for _, id := range []string{"activity", "dns", "subdomains", "crawl", "trace", "ports", "origin", "scrape"} {
		if w := u.channels[id]; w != nil {
			w.clear()
		}
	}
	u.refreshSidebar()
	u.refreshMap()
}

// clean resets the whole in-memory session — traces, map, DNS records,
// subdomains, origins, logs, the target box and the port-scan results — without
// touching the persistent database (geo cache, history, subdomain cache).
func (u *uiApp) clean() {
	// Stop anything in flight so late events cannot repopulate the view.
	u.app.Cancel()
	u.app.CancelPortScan()
	u.app.CancelScrape()
	u.finishOp()

	u.resetForOperation()

	// resetForOperation clears only the discovery/trace channels; a clean slate
	// clears every console channel too.
	for _, w := range u.channels {
		w.clear()
	}

	if u.target != nil {
		u.target.SetText("")
	}
	if u.maxHops != nil {
		u.maxHops.SetValue(u.defaultMaxHops())
	}
	if u.portDlg != nil {
		u.portDlg.clear()
	}
	if u.popup != nil {
		u.popup.Close()
		u.popup = nil
	}

	u.lastTarget = nil
	u.lastMaxHops = u.defaultMaxHops()
	u.dnsOpen = true
	if u.dnsToggle != nil {
		u.dnsToggle.SetText("▾ DNS RECORDS")
	}
	u.rightVisible = false
	if u.rightBar != nil {
		u.rightBar.Hide()
	}
	if u.status != nil {
		u.status.ShowMessage("Ready")
	}
	u.refreshSidebar()
	u.refreshMap()
	u.layoutPanes()
}

// ---- event dispatch ----

func (u *uiApp) handle(name string, payload any) {
	switch name {
	case EventHop:
		u.onHop(payload.(HopEvent))
	case EventGeo:
		u.onGeo(payload.(GeoEvent))
	case EventTarget:
		u.onTarget(payload.(TargetEvent))
	case EventTargetGeo:
		u.onTargetGeo(payload.(TargetGeoEvent))
	case EventDone:
		u.onDone(payload.(DoneEvent))
	case EventError:
		u.onError(payload.(ErrorEvent))

	case EventScanRecords:
		recs := payload.([]dnscheck.Record)
		u.records = u.records[:0]
		for _, r := range recs {
			u.records = append(u.records, dnsRecord{Type: r.Type, Name: r.Name, Value: r.Value, Priority: r.Priority})
			u.logLine("dns", "info", fmt.Sprintf("%-6s %s  %s", r.Type, r.Name, r.Value))
		}
		u.activityf("ok", "  ✓ dns records · %d resolved", len(recs))
		u.refreshSidebar()
	case EventScanTargets:
		targets := payload.([]dnscheck.Target)
		u.scanTargets = u.scanTargets[:0]
		u.lastTarget = u.lastTarget[:0]
		for _, t := range targets {
			label := strings.TrimSpace(t.Label)
			if label == "" {
				label = t.IP
			}
			u.scanTargets = append(u.scanTargets, PortScanTarget{Label: label, Host: t.IP})
			u.lastTarget = append(u.lastTarget, label)
		}
		u.status.ShowMessage(fmt.Sprintf("%d targets", len(targets)))
		u.logLine("trace", "ok", fmt.Sprintf("%d targets queued", len(targets)))
		u.activityf("info", "  ▸ tracing %d target(s) …", len(targets))
		for _, t := range targets {
			u.logLine("trace", "info", fmt.Sprintf("t%d · %s %s → %s", t.ID, t.Kind, t.Label, t.IP))
		}
	case EventScanDone:
		u.status.ShowMessage("scan complete")
		u.finishOp()
		u.scanPhase = ""
		u.tracingSubs = false
		u.scanCompleted = true
		if u.unmaskAction != nil {
			u.unmaskAction.SetEnabled(true)
		}
		u.logLine("trace", "ok", "scan complete")
		u.logLine("console", "ok", "scan complete")
		u.activityf("ok", "  ✓ complete")
		u.refreshSidebar()
	case EventSubdomains:
		u.subs = payload.([]subdomains.Result)
		for _, s := range u.subs {
			u.logLine("subdomains", "ok", fmt.Sprintf("%s [%s] %s", s.Name, s.Source, strings.Join(s.IPs, ", ")))
		}
		u.activityf("ok", "  ✓ subdomains · %d found", len(u.subs))
		u.refreshSidebar()
	case EventSubdomainLog:
		e := payload.(CrawlLogEvent)
		u.logLine("subdomains", e.Level, e.Message)
	case EventCrawlLog:
		e := payload.(CrawlLogEvent)
		u.logLine("crawl", e.Level, e.Message)
	case EventCrawlPage:
		pg := payload.(webcrawl.Page)
		u.crawlPages = append(u.crawlPages, webcrawl.Page{URL: pg.URL, Status: pg.Status})
		u.logLine("crawl", "info", fmt.Sprintf("%d %s", pg.Status, pg.URL))
	case EventCrawl:
		res := payload.(webcrawl.Result)
		u.logLine("crawl", "ok", fmt.Sprintf("%d pages crawled", len(res.Pages)))
		u.activityf("ok", "  ✓ crawl · %d pages", len(res.Pages))
	case EventBlockLog:
		e := payload.(BlockLogEvent)
		u.logLine("trace", e.Level, e.Message)
	case EventScanProgress:
		e := payload.(ScanProgressEvent)
		if e.Phase == "discover" && u.scanPhase != "discover" {
			u.logLine("trace", "info", "phase · discovering live hosts")
		}
		u.activityPhase(e.Phase)
		u.status.ShowMessage(fmt.Sprintf("%s %d/%d (%d found)", e.Phase, e.Done, e.Total, e.Found))
		u.scanPhase = e.Phase
		u.scanDone = e.Done
		u.scanTotal = e.Total
		u.refreshSidebar()

	case EventPortOpen:
		u.onPortOpen(payload.(PortOpenEvent))
	case EventPortProgress:
		e := payload.(PortScanProgressEvent)
		u.status.ShowMessage(fmt.Sprintf("ports %s %d/%d (%d open)", e.Host, e.Done, e.Total, e.Open))
	case EventPortDone:
		e := payload.(PortScanDoneEvent)
		u.status.ShowMessage(fmt.Sprintf("port scan done · %d open", e.Open))
		u.activityf("ok", "  ✓ complete · %d open", e.Open)
		if u.portDlg != nil {
			u.portDlg.finish(e)
		}
		u.finishOp()
	case EventPortError:
		e := payload.(ErrorEvent)
		u.status.ShowMessage(e.Message)
		u.logLine("ports", "error", e.Message)
		u.activityf("error", "  ! error: %s", e.Message)
		if u.portDlg != nil {
			u.portDlg.fail(e.Message)
		}
		u.finishOp()

	case EventNetData:
		u.onNetData(payload.(NetDataEvent))
	case EventNetClosed:
		e := payload.(NetClosedEvent)
		u.onNetClosed(e)
	case EventNetError:
		e := payload.(ErrorEvent)
		u.status.ShowMessage(e.Message)
		u.logLine("netcat", "error", e.Message)

	case EventDomainProgress:
		e := payload.(DomainProgressEvent)
		u.onDomainProgress(e)
	case EventOriginProgress:
		e := payload.(OriginProgressEvent)
		u.onOriginProgress(e)
	case EventOriginLog:
		e := payload.(OriginLogEvent)
		u.onOriginLog(e)
	case EventHTTPProgress:
		u.onEndpointProgress(payload.(EndpointProgressEvent))
	case EventHTTPLog:
		e := payload.(EndpointLogEvent)
		u.onEndpointLog(e)
	case EventHTTPResult:
		u.onEndpointResult(payload.(httpcheck.Report))
	case EventIPBlocksProgress:
		e := payload.(IPBlocksProgressEvent)
		u.onIPBlocksProgress(e)
	case EventScrapePage:
		u.onScrapePage(payload.(ScrapePageEvent))
	case EventScrapeAsset:
		u.onScrapeAsset(payload.(ScrapeAssetEvent))
	case EventScrapeLeak:
		u.onScrapeLeak(payload.(ScrapeLeakEvent))
	case EventScrapeProgress:
		e := payload.(ScrapeProgressEvent)
		u.status.ShowMessage(fmt.Sprintf("scrape · %d pages, %d assets, %s", e.Pages, e.Assets, formatBytes(e.Bytes)))
	case EventScrapeLog:
		e := payload.(CrawlLogEvent)
		u.logLine("scrape", e.Level, e.Message)
		if u.scrapeDlg != nil {
			u.scrapeDlg.appendLog(e.Level, e.Message)
		}
	case EventScrapeDone:
		e := payload.(ScrapeDoneEvent)
		u.status.ShowMessage(fmt.Sprintf("scrape done · %d pages, %d assets", e.Pages, e.Assets))
		if u.scrapeDlg != nil {
			u.scrapeDlg.onDone(e)
		}
		u.finishOp()
	case EventScrapeError:
		e := payload.(ErrorEvent)
		u.status.ShowMessage(e.Message)
		u.logLine("scrape", "error", e.Message)
		if u.scrapeDlg != nil {
			u.scrapeDlg.finish("error")
		}
		u.finishOp()
	}
}

func (u *uiApp) traceByID(id int) *traceState {
	for _, t := range u.traces {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (u *uiApp) ensureTrace(id int) *traceState {
	if t := u.traceByID(id); t != nil {
		return t
	}
	t := &traceState{ID: id, Color: traceColor(id), Label: "target"}
	if id == 0 {
		t.Label = "trace"
	}
	u.traces = append(u.traces, t)
	return t
}

func (u *uiApp) onHop(ev HopEvent) {
	t := u.ensureTrace(ev.Target)
	if ev.IP == "" {
		u.logLine("trace", "info", fmt.Sprintf("t%d · hop %02d · * * * · —", ev.Target, ev.Hop))
		return
	}
	t.Hops = append(t.Hops, hopData{Hop: ev.Hop, IP: ev.IP, RTTMs: ev.RTTMs, HasRTT: ev.RTTMs > 0})
	rtt := "—"
	if ev.RTTMs > 0 {
		rtt = fmt.Sprintf("%.1f ms", ev.RTTMs)
	}
	u.logLine("trace", "info", fmt.Sprintf("t%d · hop %02d · %s · %s", ev.Target, ev.Hop, ev.IP, rtt))
	u.recomputeShared()
	u.refreshMap()
	u.refreshSidebar()
}

func (u *uiApp) onGeo(ev GeoEvent) {
	t := u.ensureTrace(ev.Target)
	g := ev.Geo
	for i := range t.Hops {
		if t.Hops[i].Hop == ev.Hop {
			t.Hops[i].Geo = &g
			break
		}
	}
	u.logLine("trace", "info", fmt.Sprintf("t%d · hop %02d · geo %s", ev.Target, ev.Hop, geoPlace(g)))
	u.refreshMap()
	u.refreshSidebar()
}

func (u *uiApp) onTarget(ev TargetEvent) {
	t := u.ensureTrace(ev.Target)
	t.TargetIP = ev.IP
	if t.Label == "target" || t.Label == "trace" {
		t.Label = ev.IP
	}
	u.logLine("trace", "ok", fmt.Sprintf("t%d · target resolved %s", ev.Target, ev.IP))
	u.refreshMap()
}

func (u *uiApp) onTargetGeo(ev TargetGeoEvent) {
	t := u.ensureTrace(ev.Target)
	g := ev.Geo
	t.TargetGeo = &g
	u.logLine("trace", "info", fmt.Sprintf("t%d · target geo %s", ev.Target, geoPlace(g)))
	u.refreshMap()
}

func (u *uiApp) onDone(ev DoneEvent) {
	t := u.ensureTrace(ev.Target)
	t.Done = true
	u.cancelB.SetEnabled(false)
	u.status.ShowMessage(fmt.Sprintf("%s done · %d hops", t.Label, len(t.Hops)))
	u.logLine("trace", "ok", fmt.Sprintf("t%d · done · %d hops", ev.Target, ev.Hops))
	if ev.Target == 0 {
		u.logLine("console", "ok", fmt.Sprintf("trace complete · %d hops", ev.Hops))
		u.activityf("ok", "  ✓ trace complete · %d hops", ev.Hops)
	}
	u.refreshSidebar()
}

func (u *uiApp) onError(ev ErrorEvent) {
	if ev.Target == 0 {
		u.finishOp()
		u.status.ShowMessage(ev.Message)
		u.logLine("console", "error", ev.Message)
		if ev.Code == "missing-tool" && ev.Hint != "" {
			u.logLine("console", "error", ev.Hint)
		}
		u.logLine("trace", "error", fmt.Sprintf("t0 · error: %s", ev.Message))
		return
	}
	t := u.ensureTrace(ev.Target)
	t.Error = ev.Message
	u.logLine("trace", "error", fmt.Sprintf("t%d · error: %s", ev.Target, ev.Message))
	u.refreshSidebar()
}

// geoPlace formats a geo result as "City, Country" (plus the ASN when known),
// falling back to "unknown" so the trace log always names a location.
func geoPlace(g geolocator.GeoData) string {
	place := strings.TrimSpace(strings.Trim(strings.TrimSpace(g.City)+", "+strings.TrimSpace(g.Country), ", "))
	if place == "" {
		place = "unknown"
	}
	if asn := strings.TrimSpace(g.ASN); asn != "" {
		place += " · " + asn
	}
	return place
}

func (u *uiApp) onMarkerSelect(id string, meta any, gx, gy int) {
	m, ok := meta.(mapHit)
	if !ok {
		return
	}
	if m.Trace >= 0 {
		u.focused = m.Trace
	}
	u.selectedHop = m.Hop
	u.status.ShowMessage(fmt.Sprintf("%s · hop %d · %s", m.Label, m.Hop, m.IP))
	u.refreshSidebar()
	u.showMarkerPopup(m, gx, gy)
}

// showMarkerPopup opens the marker detail popup near the click, mirroring the
// old map popups.
func (u *uiApp) showMarkerPopup(m mapHit, gx, gy int) {
	if u.popup != nil {
		u.popup.Close()
		u.popup = nil
	}
	pop := qt.NewQWidget2()
	pop.SetWindowFlag(qt.Popup)
	v := qt.NewQVBoxLayout(pop)
	v.SetContentsMargins(10, 10, 10, 10)
	v.SetSpacing(2)

	title := qt.NewQLabel3(m.Label)
	f := qt.NewQFont()
	f.SetBold(true)
	title.SetFont(f)
	v.AddWidget(title.QWidget)

	add := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		lbl := qt.NewQLabel3(fmt.Sprintf("%-8s %s", key, value))
		lbl.SetTextInteractionFlags(qt.TextSelectableByMouse)
		v.AddWidget(lbl.QWidget)
	}

	var lat, lon float64
	hasGeo := false

	if m.Trace >= 0 {
		add("HOP", fmt.Sprintf("%d", m.Hop))
		add("IP", orDash(m.IP))
		if tr := u.traceByID(m.Trace); tr != nil {
			for _, h := range buildDisplayHops(tr) {
				if h.Hop != m.Hop {
					continue
				}
				if h.HasRTT {
					add("RTT", fmt.Sprintf("%.1f ms", h.RTTMs))
				}
				if h.Geo != nil && h.Geo.Resolved {
					add("LOC", strings.TrimSpace(h.Geo.City+" ("+h.Geo.Country+")"))
					add("LAT/LON", fmt.Sprintf("%.4f, %.4f", h.Geo.Lat, h.Geo.Lon))
					add("ASN", orDash(h.Geo.ASN))
					lat, lon, hasGeo = h.Geo.Lat, h.Geo.Lon, true
				}
				break
			}
		}
		if c := u.sharedHops[m.IP]; c >= 2 {
			add("SHARED", fmt.Sprintf("×%d", c))
		}
	} else {
		add("IP", orDash(m.IP))
		add("REVISITS", fmt.Sprintf("×%d", m.Count))
		hops := correlate(u.visibleTraces())
		if m.Hop >= 0 && m.Hop < len(hops) {
			h := hops[m.Hop]
			if h.Geo != nil && h.Geo.Resolved {
				add("LOC", strings.TrimSpace(h.Geo.City+" ("+h.Geo.Country+")"))
				add("ASN", orDash(h.Geo.ASN))
				lat, lon, hasGeo = h.Geo.Lat, h.Geo.Lon, true
			}
			add("PATHS", fmt.Sprintf("%d", h.Paths))
		}
	}

	if m.IP != "" {
		row := qt.NewQWidget2()
		rh := qt.NewQHBoxLayout(row)
		rh.SetContentsMargins(0, 6, 0, 0)
		rh.SetSpacing(6)
		if hasGeo {
			url := fmt.Sprintf("https://www.openstreetmap.org/?mlat=%f&mlon=%f#map=12/%f/%f", lat, lon, lat, lon)
			rh.AddWidget(newButton("OSM", func() {
				qt.QDesktopServices_OpenUrl(qt.NewQUrl3(url))
			}).QWidget)
		}
		rh.AddWidget(newButton("Ports", func() {
			u.portScanHost(m.IP, m.Label)
			if u.popup != nil {
				u.popup.Close()
			}
		}).QWidget)
		rh.AddWidget(newButton("Copy IP", func() {
			qt.QGuiApplication_Clipboard().SetText(m.IP)
		}).QWidget)
		rh.AddStretch()
		v.AddWidget(row)
	}

	pop.AdjustSize()
	pop.Move(gx, gy)
	pop.Show()
	u.popup = pop
}

func (u *uiApp) onMarkerContext(id string, meta any, gx, gy int) {
	m, ok := meta.(mapHit)
	if !ok || m.IP == "" {
		return
	}
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Find open ports", func() { u.portScanHost(m.IP, m.Label) })
	addMenuAction(menu, "Copy IP", func() { qt.QGuiApplication_Clipboard().SetText(m.IP) })
	menu.ExecWithPos(qt.NewQPoint2(gx, gy))
}

// ---- map ----

func (u *uiApp) recomputeShared() {
	u.sharedHops = map[string]int{}
	for _, t := range u.traces {
		seen := map[string]bool{}
		for _, h := range t.Hops {
			if h.IP == "" || seen[h.IP] {
				continue
			}
			seen[h.IP] = true
			u.sharedHops[h.IP]++
		}
	}
}

func (u *uiApp) visibleTraces() []*traceState {
	out := make([]*traceState, 0, len(u.traces))
	for _, t := range u.traces {
		if u.hidden[t.ID] {
			continue
		}
		out = append(out, t)
	}
	return out
}

func (u *uiApp) refreshMap() {
	visible := u.visibleTraces()
	model := mapview.Model{}
	located, total := 0, 0
	for _, t := range visible {
		for _, h := range buildDisplayHops(t) {
			total++
			if isLocated(h.Geo) {
				located++
			}
		}
	}

	if u.correlate {
		hops := correlate(visible)
		for i, h := range hops {
			radius := 4.0 + math.Min(float64(h.Count-1), 6)*1.4
			label := ""
			if h.Count > 1 {
				label = fmt.Sprintf("×%d", h.Count)
			}
			model.Markers = append(model.Markers, mapview.Marker{
				X: h.Pos[0], Y: h.Pos[1], Radius: radius, Color: correlationColor(h.Count),
				Fill: true, Label: label, Tooltip: h.IP,
				ID:   fmt.Sprintf("corr:%d", i),
				Meta: mapHit{Trace: -1, Hop: i, IP: h.IP, Label: "correlated hop", Count: h.Count},
			})
		}
	} else {
		for _, t := range visible {
			hops := buildDisplayHops(t)
			var coords [][2]float64
			hasTarget := false
			for _, h := range hops {
				if h.IsTarget {
					hasTarget = true
				}
			}
			last := len(hops) - 1
			for idx, h := range hops {
				if !isLocated(h.Geo) {
					continue
				}
				x, y := merc(h.Geo.Lat, h.Geo.Lon)
				coords = append(coords, [2]float64{x, y})
				isDest := h.IsTarget || (!hasTarget && idx == last)
				fill := isDest || idx == 0
				radius := 4.0
				if isDest {
					radius = 6
				} else if u.sharedHops[h.IP] >= 2 {
					radius = 6
				} else if idx == 0 {
					radius = 5
				}
				tip := fmt.Sprintf("%s\nHOP %d · %s", t.Label, h.Hop, h.IP)
				if h.Geo != nil {
					tip += fmt.Sprintf("\nLOC %s (%s)\nASN %s\n%.4f, %.4f", h.Geo.City, h.Geo.Country, h.Geo.ASN, h.Geo.Lat, h.Geo.Lon)
				}
				if u.sharedHops[h.IP] >= 2 {
					tip += fmt.Sprintf("\nSHARED ×%d", u.sharedHops[h.IP])
				}
				model.Markers = append(model.Markers, mapview.Marker{
					X: x, Y: y, Radius: radius, Color: t.Color, Fill: fill,
					Ring: u.sharedHops[h.IP] >= 2, Tooltip: tip,
					ID:   fmt.Sprintf("t%d:h%d", t.ID, h.Hop),
					Meta: mapHit{Trace: t.ID, Hop: h.Hop, IP: h.IP, Label: t.Label},
				})
			}
			if len(coords) >= 2 {
				model.Routes = append(model.Routes, mapview.Route{Color: t.Color, Points: buildRoute(coords)})
			}
		}
	}

	for _, o := range u.origins {
		x, y := merc(o.Lat, o.Lon)
		model.Origins = append(model.Origins, mapview.Origin{
			X: x, Y: y, Label: o.Label, Tooltip: fmt.Sprintf("ORIGIN %s\n%s\n%s", o.IP, o.Label, o.Verdict),
			ID: "origin:" + o.IP, Meta: mapHit{IP: o.IP, Label: o.Label},
		})
	}

	// TRACES legend overlay: one swatch per visible trace.
	for _, t := range visible {
		model.Legend = append(model.Legend, mapview.LegendEntry{Color: t.Color, Label: t.Label})
	}

	if u.correlate {
		visits := 0
		for _, t := range visible {
			for _, h := range buildDisplayHops(t) {
				if isLocated(h.Geo) {
					visits++
				}
			}
		}
		model.HUD = fmt.Sprintf("%d UNIQUE · %d VISITS", len(model.Markers), visits)
	} else {
		if len(u.sharedHops) > 0 {
			model.HUD = fmt.Sprintf("%d/%d LOCATED · %d SHARED", located, total, len(u.sharedHops))
		} else {
			model.HUD = fmt.Sprintf("%d/%d LOCATED", located, total)
		}
	}
	u.mapView.SetModel(model)
	u.updateStatusStats(located, total)
}

// updateStatusStats refreshes the permanent located/shared status readout.
func (u *uiApp) updateStatusStats(located, total int) {
	if u.statusStats == nil {
		return
	}
	parts := []string{fmt.Sprintf("located %d/%d", located, total)}
	if shared := len(u.sharedHops); shared > 0 {
		parts = append(parts, fmt.Sprintf("shared %d", shared))
	}
	if hidden := len(u.hidden); hidden > 0 {
		parts = append(parts, fmt.Sprintf("hidden %d", hidden))
	}
	u.statusStats.SetText(strings.Join(parts, " · "))
}

// ---- sidebar ----

func (u *uiApp) refreshSidebar() {
	// Hops / correlation share the left sidebar's main pane.
	sel := u.traceByID(u.focused)
	if sel == nil && len(u.traces) > 0 {
		sel = u.traces[0]
	}

	u.hopTree.Clear()
	hopCount := 0
	if sel != nil {
		hops := buildDisplayHops(sel)
		hopCount = len(hops)
		u.hopTitle.SetText(sel.Label)
		for _, h := range hops {
			item := qt.NewQTreeWidgetItem3(u.hopTree)
			item.SetText(0, fmt.Sprintf("%d", h.Hop))
			ip := h.IP
			if ip == "" {
				ip = "*"
			}
			if h.IsTarget {
				ip += "  (target)"
			}
			item.SetText(1, ip)
			if h.HasRTT {
				item.SetText(2, fmt.Sprintf("%.1f ms", h.RTTMs))
			} else {
				item.SetText(2, "—")
			}
			if h.Geo != nil && h.Geo.Resolved {
				item.SetText(3, strings.TrimSpace(h.Geo.City+" "+h.Geo.Country))
			} else {
				item.SetText(3, "—")
			}
		}
	} else {
		u.hopTitle.SetText("HOPS")
	}
	u.hopsCount.SetText(fmt.Sprintf("%d", hopCount))

	// Targets pane (only shown when more than one trace exists). The checkbox
	// toggles a trace's visibility on the map.
	u.populatingTraces = true
	u.traceTree.BlockSignals(true)
	u.traceTree.Clear()
	for _, t := range u.traces {
		item := qt.NewQTreeWidgetItem3(u.traceTree)
		item.SetFlags(item.Flags() | qt.ItemIsUserCheckable)
		mark := ""
		if t.Done {
			mark = " ✓"
		} else if t.Error != "" {
			mark = " !"
		}
		item.SetText(0, fmt.Sprintf("%d%s", t.ID, mark))
		item.SetText(1, t.Label)
		item.SetText(2, t.TargetIP)
		item.SetForeground(1, qt.NewQBrush3(qt.NewQColor6(t.Color)))
		if u.hidden[t.ID] {
			item.SetCheckState(0, qt.Unchecked)
		} else {
			item.SetCheckState(0, qt.Checked)
		}
	}
	u.traceTree.BlockSignals(false)
	u.populatingTraces = false
	u.targetsCount.SetText(fmt.Sprintf("%d", len(u.traces)))
	if len(u.traces) > 1 {
		u.targetsPane.Show()
	} else {
		u.targetsPane.Hide()
	}

	// Correlation pane.
	u.corrTree.Clear()
	corrCount := 0
	for _, h := range correlate(u.traces) {
		if h.Count < 2 {
			continue
		}
		corrCount++
		item := qt.NewQTreeWidgetItem3(u.corrTree)
		item.SetText(0, h.IP)
		item.SetText(1, fmt.Sprintf("×%d", h.Count))
		item.SetText(2, fmt.Sprintf("%d", h.Paths))
	}
	u.corrCount.SetText(fmt.Sprintf("%d", corrCount))
	if u.correlate {
		u.corrPane.Show()
		u.hopsPane.Hide()
	} else {
		u.corrPane.Hide()
		u.hopsPane.Show()
	}

	// DNS records (right sidebar).
	u.dnsTree.Clear()
	for _, r := range u.records {
		item := qt.NewQTreeWidgetItem3(u.dnsTree)
		item.SetText(0, r.Type)
		val := r.Value
		if r.Priority > 0 {
			val += fmt.Sprintf(" · %d", r.Priority)
		}
		item.SetText(1, val)
	}
	u.dnsCount.SetText(fmt.Sprintf("%d", len(u.records)))
	if len(u.records) > 0 {
		u.dnsPane.Show()
	} else {
		u.dnsPane.Hide()
	}

	// Subdomains (right sidebar).
	u.populatingSubs = true
	u.subTree.BlockSignals(true)
	u.subTree.Clear()
	for _, s := range u.subs {
		item := qt.NewQTreeWidgetItem3(u.subTree)
		item.SetFlags(item.Flags() | qt.ItemIsUserCheckable)
		item.SetText(0, s.Name)
		item.SetText(1, fmt.Sprintf("%d", len(s.IPs)))
		item.SetText(2, s.Source)
		item.SetForeground(2, qt.NewQBrush3(qt.NewQColor6(subSourceColor(s.Source))))
		if u.selectedSubs[s.Name] {
			item.SetCheckState(0, qt.Checked)
		} else {
			item.SetCheckState(0, qt.Unchecked)
		}
	}
	u.subTree.BlockSignals(false)
	u.populatingSubs = false
	u.subsCount.SetText(fmt.Sprintf("%d", len(u.subs)))

	// While discovery runs with nothing found yet, show the phase progress.
	waiting := len(u.subs) == 0 && isDiscoveryPhase(u.scanPhase)
	if waiting {
		u.subWait.SetText(fmt.Sprintf("%s · %d/%d", scanPhaseLabel(u.scanPhase), u.scanDone, u.scanTotal))
		u.subWait.Show()
	} else {
		u.subWait.Hide()
	}
	if len(u.subs) > 0 || waiting {
		u.subsPane.Show()
	} else {
		u.subsPane.Hide()
	}
	u.updateSubButtons()

	// The discovery sidebar only appears once there is something to show.
	discovery := len(u.records) > 0 || len(u.subs) > 0 || waiting
	if discovery != u.rightVisible {
		u.rightVisible = discovery
		if u.rightBar != nil {
			if discovery {
				u.rightBar.Show()
			} else {
				u.rightBar.Hide()
			}
		}
		u.layoutPanes()
	}

	if u.saveHistAction != nil {
		u.saveHistAction.SetEnabled(len(u.traces) > 0)
	}
}

// layoutPanes sizes the splitter so the map keeps the flexible middle share and
// the sidebars stay narrow, instead of the three panes splitting evenly.
func (u *uiApp) layoutPanes() {
	if u.split == nil {
		return
	}
	w := u.win.Width()
	if w <= 0 {
		w = 1280
	}
	left := 300
	right := 0
	if u.rightVisible {
		right = 340
	}
	mid := w - left - right
	if mid < 320 {
		mid = 320
	}
	u.split.SetSizes([]int{left, mid, right})
}

func (u *uiApp) hopClicked(item *qt.QTreeWidgetItem) {
	if item == nil {
		return
	}
	var hopN int
	fmt.Sscanf(item.Text(0), "%d", &hopN)
	u.selectedHop = hopN
	sel := u.traceByID(u.focused)
	if sel == nil && len(u.traces) > 0 {
		sel = u.traces[0]
	}
	if sel != nil {
		for _, h := range buildDisplayHops(sel) {
			if h.Hop == hopN && isLocated(h.Geo) {
				x, y := merc(h.Geo.Lat, h.Geo.Lon)
				u.mapView.Focus(x, y)
				break
			}
		}
	}
}

func (u *uiApp) traceClicked(item *qt.QTreeWidgetItem) {
	if item == nil {
		return
	}
	var id int
	fmt.Sscanf(item.Text(0), "%d", &id)
	u.focused = id
	u.selectedHop = -1
	u.refreshMap()
	u.refreshSidebar()
}

// traceItemChanged keeps the hidden-trace set in sync when a row's visibility
// checkbox is toggled.
func (u *uiApp) traceItemChanged(item *qt.QTreeWidgetItem, col int) {
	if item == nil || col != 0 || u.populatingTraces {
		return
	}
	var id int
	if _, err := fmt.Sscanf(item.Text(0), "%d", &id); err != nil {
		return
	}
	if item.CheckState(0) == qt.Checked {
		delete(u.hidden, id)
	} else {
		u.hidden[id] = true
	}
	u.refreshMap()
}

// hopContext offers per-hop actions from the sidebar.
func (u *uiApp) hopContext(pos *qt.QPoint) {
	item := u.hopTree.ItemAt(pos)
	if item == nil {
		return
	}
	ip := ipFromHopLabel(item.Text(1))
	if ip == "" {
		return
	}
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Find open ports", func() { u.portScanHost(ip, ip) })
	addMenuAction(menu, "Trace this host", func() { u.traceHost(ip) })
	addMenuAction(menu, "Copy IP", func() { qt.QGuiApplication_Clipboard().SetText(ip) })
	gp := u.hopTree.MapToGlobal(qt.NewQPointF3(float64(pos.X()), float64(pos.Y())))
	menu.ExecWithPos(qt.NewQPoint2(int(gp.X()), int(gp.Y())))
}

// traceContext offers per-trace actions from the sidebar.
func (u *uiApp) traceContext(pos *qt.QPoint) {
	item := u.traceTree.ItemAt(pos)
	if item == nil {
		return
	}
	var id int
	fmt.Sscanf(item.Text(0), "%d", &id)
	host := strings.TrimSpace(item.Text(2))
	menu := qt.NewQMenu2()
	addMenuAction(menu, "Toggle visibility", func() {
		if u.hidden[id] {
			delete(u.hidden, id)
		} else {
			u.hidden[id] = true
		}
		u.refreshMap()
		u.refreshSidebar()
	})
	if host != "" {
		addMenuAction(menu, "Find open ports", func() { u.portScanHost(host, host) })
		addMenuAction(menu, "Trace this host", func() { u.traceHost(host) })
		addMenuAction(menu, "Copy IP", func() { qt.QGuiApplication_Clipboard().SetText(host) })
	}
	gp := u.traceTree.MapToGlobal(qt.NewQPointF3(float64(pos.X()), float64(pos.Y())))
	menu.ExecWithPos(qt.NewQPoint2(int(gp.X()), int(gp.Y())))
}

// ipFromHopLabel strips the sidebar's " (target)" decoration from a hop IP.
func ipFromHopLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "*" {
		return ""
	}
	label = strings.TrimSuffix(label, "(target)")
	return strings.TrimSpace(label)
}

// subItemChanged keeps the selection set in sync when a subdomain checkbox is
// toggled.
func (u *uiApp) subItemChanged(item *qt.QTreeWidgetItem, col int) {
	if item == nil || col != 0 || u.populatingSubs {
		return
	}
	name := item.Text(0)
	if item.CheckState(0) == qt.Checked {
		u.selectedSubs[name] = true
	} else {
		delete(u.selectedSubs, name)
	}
	u.updateSubButtons()
}

func (u *uiApp) selectAllSubs() {
	for _, s := range u.subs {
		u.selectedSubs[s.Name] = true
	}
	u.refreshSidebar()
}

func (u *uiApp) clearSubs() {
	u.selectedSubs = map[string]bool{}
	u.refreshSidebar()
}

func (u *uiApp) updateSubButtons() {
	n := 0
	for _, s := range u.subs {
		if u.selectedSubs[s.Name] {
			n++
		}
	}
	if u.subTraceBtn != nil {
		u.subTraceBtn.SetText(fmt.Sprintf("Trace %d", n))
		u.subTraceBtn.SetEnabled(n > 0 && !u.tracingSubs)
	}
}

// traceSelectedSubs traces only the subdomains the user ticked.
func (u *uiApp) traceSelectedSubs() {
	var hosts []string
	for _, s := range u.subs {
		if u.selectedSubs[s.Name] {
			hosts = append(hosts, s.Name)
		}
	}
	if len(hosts) == 0 {
		return
	}
	domain := cleanDomain(u.target.Text())
	u.traces = nil
	u.hidden = map[int]bool{}
	u.focused = -1
	u.selectedHop = -1
	u.sharedHops = map[string]int{}
	u.tracingSubs = true
	u.lastMaxHops = u.maxHops.Value()
	u.startOp(fmt.Sprintf("trace %d subs", len(hosts)))
	u.openChannel("trace")
	word := "hosts"
	if len(hosts) == 1 {
		word = "host"
	}
	u.startActivity(fmt.Sprintf("trace %d selected %s", len(hosts), word), []activityStep{
		{Label: "resolve selected hosts", Enabled: true},
		{Label: "traceroute", Enabled: true},
		{Label: "geolocate hops", Enabled: true},
	})
	u.logLine("trace", "info", fmt.Sprintf("▶ trace %d selected %s", len(hosts), word))
	u.refreshMap()
	u.refreshSidebar()
	go func() {
		if err := u.app.TraceTargets(TraceTargetsRequest{Domain: domain, MaxHops: u.maxHops.Value(), Hosts: hosts}); err != nil {
			mainthread.Start(func() {
				u.tracingSubs = false
				u.finishOp()
				u.updateSubButtons()
				u.status.ShowMessage(err.Error())
			})
		}
	}()
}

// toggleDNSPanel collapses/expands the DNS records list.
func (u *uiApp) toggleDNSPanel() {
	u.dnsOpen = !u.dnsOpen
	if u.dnsOpen {
		u.dnsTree.Show()
		u.dnsToggle.SetText("▾ DNS RECORDS")
	} else {
		u.dnsTree.Hide()
		u.dnsToggle.SetText("▸ DNS RECORDS")
	}
}

// subSourceColor maps a discovery source to the colour the old UI used.
func subSourceColor(source string) string {
	switch {
	case strings.HasPrefix(source, "brute"):
		return "#2dd4ef"
	case strings.HasPrefix(source, "ptr"):
		return "#3ddc97"
	case strings.HasPrefix(source, "spf"), strings.HasPrefix(source, "dmarc"):
		return "#f5b642"
	case strings.HasPrefix(source, "srv"):
		return "#c4b5fd"
	case strings.HasPrefix(source, "crawl"):
		return "#f472b6"
	default:
		return "#9db4c8"
	}
}

func isDiscoveryPhase(phase string) bool {
	switch phase {
	case "subdomains", "ptr", "sweep", "crawl":
		return true
	}
	return false
}

func scanPhaseLabel(phase string) string {
	switch phase {
	case "subdomains":
		return "brute forcing"
	case "ptr":
		return "reverse DNS"
	case "sweep":
		return "sweeping /24s"
	case "crawl":
		return "crawling"
	default:
		return "discovering"
	}
}

// traceHost starts a fresh single trace for a specific host (used from port-scan
// results and the map context menu).
func (u *uiApp) traceHost(host string) {
	if strings.TrimSpace(host) == "" {
		return
	}
	u.resetForOperation()
	u.lastMaxHops = u.maxHops.Value()
	u.startOp("trace " + host)
	u.openChannel("trace")
	u.startActivity(fmt.Sprintf("trace %s · max %d hops", host, u.maxHops.Value()), []activityStep{
		{Label: "resolve target", Enabled: true},
		{Label: "traceroute", Enabled: true},
		{Label: "geolocate hops", Enabled: true},
	})
	u.logLine("trace", "info", fmt.Sprintf("▶ trace %s · max %d hops", host, u.maxHops.Value()))
	go func() {
		err := u.app.Trace(TraceRequest{Target: host, MaxHops: u.maxHops.Value()})
		u.afterOp(err)
	}()
}

// setCorrelate switches between the per-trace route view and the correlated
// (deduplicated hops) view.
func (u *uiApp) setCorrelate(on bool) {
	u.correlate = on
	if u.corrAction != nil {
		u.corrAction.SetChecked(on)
	}
	u.refreshMap()
	u.refreshSidebar()
}

// ---- theme ----

func (u *uiApp) toggleTheme() {
	u.themeDark = !u.themeDark
	if u.themeDark {
		u.mapView.SetTheme(mapview.DarkTheme())
	} else {
		u.mapView.SetTheme(mapview.LightTheme())
	}
}

// ---- badge ----

func (u *uiApp) updateBadge() {
	text := strings.TrimSpace(u.target.Text())
	cidr, ports, ok := parseBlockTarget(text)
	if !ok {
		u.badge.SetText("")
		return
	}
	if ports == "" {
		u.badge.SetText("PORTS · top100")
	} else {
		u.badge.SetText("PORTS · " + ports)
	}
	_ = cidr
}

func (u *uiApp) show() {
	u.win.Show()
	u.layoutPanes()
}

func (u *uiApp) run() {
	u.win.Show()
	u.layoutPanes()
	u.checkTools()
	qt.QApplication_Exec()
}

// checkTools warns at startup when no supported traceroute binary is present,
// so the user learns why tracing will fail before they try it.
func (u *uiApp) checkTools() {
	status := u.app.CheckTools()
	if status.Available {
		return
	}
	message := status.Message
	if message == "" {
		message = "No supported traceroute tool was found on this system."
	}
	if status.Hint != "" {
		message += "\n\n" + status.Hint
	}
	qt.QMessageBox_Warning(u.win.QWidget, "Traceroute tool not found", message)
}

// netcat placeholder is implemented in ui_netcat.go
func (u *uiApp) portScanHost(host, label string) {
	u.openPortScanFor(host, label)
}

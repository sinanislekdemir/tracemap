package main

import (
	"fmt"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"

	"traceroute/internal/scrape"
)

// scrapeIndexDialog is the archive browser: pick a stored job, list its pages
// and media, and full-text search across the whole archive. It is read-only
// apart from deleting a job; running a scrape is the separate scrapeDialog.
type scrapeIndexDialog struct {
	u   *uiApp
	win *qt.QDialog

	jobCombo *qt.QComboBox
	jobs     []scrape.JobSummary
	info     *qt.QLabel

	tabs         *qt.QTabWidget
	pageTable    *qt.QTreeWidget
	assetTable   *qt.QTreeWidget
	assetKind    *qt.QComboBox
	assetPreview *qt.QLabel
	leakTable    *qt.QTreeWidget

	searchField *qt.QComboBox
	searchQuery *qt.QLineEdit
	searchTable *qt.QTreeWidget

	pages  []scrape.PageSummary
	assets []scrape.AssetSummary
	leaks  []scrape.LeakSummary
	hits   []scrape.Hit
}

// openScrapeIndex opens the archive browser.
func (u *uiApp) openScrapeIndex() {
	if !u.app.ScrapeEnabled() {
		u.status.ShowMessage("scraping is disabled: no data directory (set TRACEROUTE_DATA)")
		return
	}
	d := &scrapeIndexDialog{u: u}
	d.build()
	u.scrapeIndexDlg = d
	d.refreshJobs()
	d.loadSelectedJob()
	d.win.Show()
	d.win.Raise()
	d.win.ActivateWindow()
}

func (d *scrapeIndexDialog) build() {
	d.win = newFloatingDialog(d.u.win.QWidget)
	d.win.SetWindowTitle("Scrape index")
	d.win.Resize(960, 720)
	v := qt.NewQVBoxLayout(d.win.QWidget)

	bar := qt.NewQWidget2()
	bh := qt.NewQHBoxLayout(bar)
	bh.SetContentsMargins(0, 0, 0, 0)
	bh.AddWidget(qt.NewQLabel3("Job").QWidget)
	d.jobCombo = qt.NewQComboBox2()
	d.jobCombo.SetMinimumWidth(320)
	d.jobCombo.OnCurrentIndexChanged(func(int) { d.loadSelectedJob() })
	bh.AddWidget(d.jobCombo.QWidget)
	bh.AddWidget(newButton("Refresh", func() { d.refreshJobs(); d.loadSelectedJob() }).QWidget)
	bh.AddWidget(newButton("Delete job", func() { d.deleteJob() }).QWidget)
	bh.AddStretch()
	v.AddWidget(bar)

	d.info = qt.NewQLabel3("")
	d.info.SetWordWrap(true)
	v.AddWidget(d.info.QWidget)

	d.tabs = qt.NewQTabWidget2()
	v.AddWidget2(d.tabs.QWidget, 1)

	page := qt.NewQWidget2()
	pv := qt.NewQVBoxLayout(page)
	d.pageTable = newScrapePageTable(func(pos *qt.QPoint) { d.pageMenu(pos) }, func() { d.openSelectedPage() })
	pv.AddWidget2(d.pageTable.QWidget, 1)
	d.tabs.AddTab(page, "Pages")

	d.tabs.AddTab(d.buildAssetsTab(), "Assets")

	leaks := qt.NewQWidget2()
	lv := qt.NewQVBoxLayout(leaks)
	d.leakTable = newScrapeLeakTable(func(pos *qt.QPoint) { d.leakMenu(pos) }, func() { d.openSelectedLeak() })
	lv.AddWidget2(d.leakTable.QWidget, 1)
	lv.AddWidget(qt.NewQLabel3("Open directory listings (autoindex) found by the index test for this job.").QWidget)
	d.tabs.AddTab(leaks, "Leaks")

	d.tabs.AddTab(d.buildSearchTab(), "Search")
}

func (d *scrapeIndexDialog) buildAssetsTab() *qt.QWidget {
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

func (d *scrapeIndexDialog) buildSearchTab() *qt.QWidget {
	search := qt.NewQWidget2()
	sv := qt.NewQVBoxLayout(search)

	bar := qt.NewQWidget2()
	bh := qt.NewQHBoxLayout(bar)
	bh.SetContentsMargins(0, 0, 0, 0)
	bh.AddWidget(qt.NewQLabel3("Search in").QWidget)
	d.searchField = qt.NewQComboBox2()
	d.searchField.AddItems([]string{"all fields", "title", "metadata", "url", "content", "full html", "filename"})
	bh.AddWidget(d.searchField.QWidget)
	d.searchQuery = qt.NewQLineEdit2()
	d.searchQuery.SetPlaceholderText("keyword(s) — case-insensitive")
	d.searchQuery.OnReturnPressed(func() { d.runSearch() })
	bh.AddWidget2(d.searchQuery.QWidget, 1)
	bh.AddWidget(newButton("Search", func() { d.runSearch() }).QWidget)
	sv.AddWidget(bar)

	d.searchTable = qt.NewQTreeWidget2()
	d.searchTable.SetColumnCount(4)
	d.searchTable.SetHeaderLabels([]string{"Type", "Match", "URL / Filename", "Snippet"})
	d.searchTable.SetContextMenuPolicy(qt.CustomContextMenu)
	d.searchTable.OnCustomContextMenuRequested(func(pos *qt.QPoint) { d.hitMenu(pos) })
	d.searchTable.OnItemDoubleClicked(func(item *qt.QTreeWidgetItem, col int) { d.openSelectedHit() })
	sv.AddWidget2(d.searchTable.QWidget, 1)

	hint := qt.NewQLabel3("The search covers the job selected above (or every job when \"All jobs\" is chosen).")
	hint.SetWordWrap(true)
	sv.AddWidget(hint.QWidget)
	return search
}

func (d *scrapeIndexDialog) refreshJobs() {
	jobs, err := d.u.app.ListScrapeJobs()
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	prev := d.selectedJobID()
	d.jobs = jobs
	d.jobCombo.Clear()
	d.jobCombo.AddItem("All jobs")
	for _, j := range jobs {
		when := time.UnixMilli(j.CreatedAt).Format("2006-01-02 15:04")
		d.jobCombo.AddItem(fmt.Sprintf("#%d %s · %d pages · %d assets · %s", j.ID, j.Label, j.Pages, j.Assets, when))
	}
	// Restore the previous selection when it still exists.
	for i, j := range jobs {
		if j.ID == prev {
			d.jobCombo.SetCurrentIndex(i + 1)
			break
		}
	}
}

// selectedJobID returns the selected job id, or 0 for "All jobs".
func (d *scrapeIndexDialog) selectedJobID() int64 {
	idx := d.jobCombo.CurrentIndex()
	if idx <= 0 || idx > len(d.jobs) {
		return 0
	}
	return d.jobs[idx-1].ID
}

func (d *scrapeIndexDialog) loadSelectedJob() {
	jobID := d.selectedJobID()
	if jobID == 0 {
		d.pages = nil
		d.assets = nil
		d.leaks = nil
		d.info.SetText(fmt.Sprintf("%d job(s) in the archive — pick one to browse, or use the Search tab across all.", len(d.jobs)))
		d.renderPages()
		d.renderAssets()
		d.renderLeaks()
		return
	}
	pages, err := d.u.app.ListScrapePages(jobID)
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	assets, err := d.u.app.ListScrapeAssets(jobID, "")
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	leaks, err := d.u.app.ListScrapeLeaks(jobID)
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	d.pages = pages
	d.assets = assets
	d.leaks = leaks
	d.renderPages()
	d.renderAssets()
	d.renderLeaks()
	d.describeJob(jobID)
}

func (d *scrapeIndexDialog) renderLeaks() {
	fillScrapeLeakTable(d.leakTable, d.leaks)
}

func (d *scrapeIndexDialog) leakMenu(pos *qt.QPoint) {
	item := d.leakTable.ItemAt(pos)
	if item == nil {
		return
	}
	d.leakTable.SetCurrentItem(item)
	if l, ok := scrapeLeakAt(d.leakTable, d.leaks); ok {
		scrapeLeakMenu(d.leakTable, pos, l)
	}
}

func (d *scrapeIndexDialog) openSelectedLeak() {
	if l, ok := scrapeLeakAt(d.leakTable, d.leaks); ok {
		qt.QDesktopServices_OpenUrl(qt.NewQUrl3(l.URL))
	}
}

func (d *scrapeIndexDialog) describeJob(jobID int64) {
	for _, j := range d.jobs {
		if j.ID != jobID {
			continue
		}
		parts := []string{
			fmt.Sprintf("#%d %s", j.ID, j.Label),
			"status " + j.Status,
			fmt.Sprintf("depth %d", j.Depth),
			"mode " + j.Mode,
			"scope " + j.Scope,
			fmt.Sprintf("%d pages, %d assets, %s", j.Pages, j.Assets, formatBytes(j.Bytes)),
			time.UnixMilli(j.CreatedAt).Format("2006-01-02 15:04"),
		}
		if j.Leaks > 0 {
			parts = append(parts, fmt.Sprintf("%d index leak(s)", j.Leaks))
		}
		if kws := decodeKeywordList(j.Keywords); len(kws) > 0 {
			parts = append(parts, "keywords: "+strings.Join(kws, ", "))
		}
		d.info.SetText(strings.Join(parts, " · "))
		return
	}
}

func (d *scrapeIndexDialog) deleteJob() {
	jobID := d.selectedJobID()
	if jobID == 0 {
		d.u.status.ShowMessage("select a job to delete")
		return
	}
	if err := d.u.app.DeleteScrapeJob(jobID); err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	d.u.status.ShowMessage(fmt.Sprintf("deleted job #%d", jobID))
	d.refreshJobs()
	d.loadSelectedJob()
}

func (d *scrapeIndexDialog) renderPages() {
	fillScrapePageTable(d.pageTable, d.pages)
}

func (d *scrapeIndexDialog) renderAssets() {
	fillScrapeAssetTable(d.assetTable, d.assets, d.assetKind.CurrentText())
}

func (d *scrapeIndexDialog) runSearch() {
	query := strings.TrimSpace(d.searchQuery.Text())
	if query == "" {
		d.searchTable.Clear()
		d.hits = nil
		return
	}
	hits, err := d.u.app.SearchScrape(ScrapeQuery{
		JobID: d.selectedJobID(),
		Field: scrapeSearchField(d.searchField.CurrentIndex()),
		Query: query,
	})
	if err != nil {
		d.u.status.ShowMessage(err.Error())
		return
	}
	d.hits = hits
	d.searchTable.Clear()
	for _, h := range hits {
		item := qt.NewQTreeWidgetItem3(d.searchTable)
		item.SetText(0, h.Kind)
		item.SetText(1, h.Title)
		item.SetText(2, h.URL)
		item.SetText(3, h.Snippet)
	}
	d.u.status.ShowMessage(fmt.Sprintf("%d result(s)", len(hits)))
}

func (d *scrapeIndexDialog) selectedPage() (scrape.PageSummary, bool) {
	return scrapePageAt(d.pageTable, d.pages)
}

func (d *scrapeIndexDialog) selectedAsset() (scrape.AssetSummary, bool) {
	return scrapeAssetAt(d.assetTable, d.assets)
}

func (d *scrapeIndexDialog) pageMenu(pos *qt.QPoint) {
	item := d.pageTable.ItemAt(pos)
	if item == nil {
		return
	}
	d.pageTable.SetCurrentItem(item)
	if p, ok := d.selectedPage(); ok {
		scrapePageMenu(d.u, d.win.QWidget, d.pageTable, pos, p)
	}
}

func (d *scrapeIndexDialog) assetMenu(pos *qt.QPoint) {
	item := d.assetTable.ItemAt(pos)
	if item == nil {
		return
	}
	d.assetTable.SetCurrentItem(item)
	if a, ok := d.selectedAsset(); ok {
		scrapeAssetMenu(d.u, d.win.QWidget, d.assetTable, pos, a)
	}
}

func (d *scrapeIndexDialog) hitMenu(pos *qt.QPoint) {
	item := d.searchTable.ItemAt(pos)
	if item == nil {
		return
	}
	d.searchTable.SetCurrentItem(item)
	idx := d.searchTable.IndexOfTopLevelItem(item)
	if idx < 0 || idx >= len(d.hits) {
		return
	}
	hit := d.hits[idx]
	menu := qt.NewQMenu2()
	if hit.Kind == "page" {
		addMenuAction(menu, "Preview", func() { d.u.previewScrapePage(d.win.QWidget, hit.ID) })
		addMenuAction(menu, "View raw HTML", func() { d.u.viewScrapeHTML(d.win.QWidget, hit.ID) })
	} else {
		addMenuAction(menu, "Open", func() { d.u.openScrapeAssetFile(hit.ID) })
		addMenuAction(menu, "Reveal in file manager", func() { d.u.revealScrapeAsset(hit.ID) })
	}
	addMenuAction(menu, "Open in browser", func() { qt.QDesktopServices_OpenUrl(qt.NewQUrl3(hit.URL)) })
	addMenuAction(menu, "Copy URL", func() { qt.QGuiApplication_Clipboard().SetText(hit.URL) })
	execScrapeMenu(menu, d.searchTable, pos)
}

func (d *scrapeIndexDialog) openSelectedPage() {
	if p, ok := d.selectedPage(); ok {
		d.u.previewScrapePage(d.win.QWidget, p.ID)
	}
}

func (d *scrapeIndexDialog) openSelectedAsset() {
	if a, ok := d.selectedAsset(); ok {
		d.u.openScrapeAssetFile(a.ID)
	}
}

func (d *scrapeIndexDialog) updateAssetPreview() {
	a, ok := d.selectedAsset()
	if !ok {
		d.assetPreview.SetPixmap(qt.NewQPixmap())
		d.assetPreview.SetText("select an image to preview")
		return
	}
	d.u.previewScrapeAsset(d.assetPreview, a)
}

func (d *scrapeIndexDialog) openSelectedHit() {
	item := d.searchTable.CurrentItem()
	if item == nil {
		return
	}
	idx := d.searchTable.IndexOfTopLevelItem(item)
	if idx < 0 || idx >= len(d.hits) {
		return
	}
	if d.hits[idx].Kind == "asset" {
		d.u.openScrapeAssetFile(d.hits[idx].ID)
		return
	}
	d.u.previewScrapePage(d.win.QWidget, d.hits[idx].ID)
}

// decodeKeywordList renders the job's stored keyword JSON for display.
func decodeKeywordList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

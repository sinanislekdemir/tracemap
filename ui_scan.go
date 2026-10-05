package main

import (
	"strings"

	qt "github.com/mappu/miqt/qt6"
)

// scanDefaults mirror the web frontend's presets.
func scanBasic() (ScanOptions, int) {
	return ScanOptions{ExpandNS: true, CrawlMaxPages: 25, AutoTrace: true, MaxTargets: 12}, 30
}

func scanStandard() (ScanOptions, int) {
	return ScanOptions{
		ExpandNS: true, BruteForce: true, PTR: true, Services: true, Crawl: true,
		CrawlMaxPages: 25, AutoTrace: false, MaxTargets: 24,
	}, 30
}

func scanDeep() (ScanOptions, int) {
	return ScanOptions{
		ExpandNS: true, BruteForce: true, PTR: true, Sweep24: true, Services: true,
		Crawl: true, CrawlMaxPages: 100, AutoTrace: true, MaxTargets: 200,
	}, 100
}

// scanOptionsUI is the advanced-scan options dialog.
type scanOptionsUI struct {
	domain   *qt.QLineEdit
	maxHops  *qt.QSpinBox
	expandNS *qt.QCheckBox
	brute    *qt.QCheckBox
	ptr      *qt.QCheckBox
	sweep    *qt.QCheckBox
	services *qt.QCheckBox
	crawl    *qt.QCheckBox
	review   *qt.QRadioButton
	auto     *qt.QRadioButton

	wordlist    *qt.QLineEdit
	wordlistRow *qt.QWidget
	crawlPages  *qt.QSpinBox
	crawlRow    *qt.QWidget
	maxTargets  *qt.QSpinBox

	subConcurrency *qt.QSpinBox
	subRate        *qt.QSpinBox
}

// openScanDialog opens the advanced-scan options window for the current target.
// A CIDR target switches to the block port scanner instead.
func (u *uiApp) openScanDialog() {
	target := cleanDomain(u.target.Text())
	if target == "" {
		u.status.ShowMessage("enter a domain first")
		return
	}
	if _, _, ok := parseBlockTarget(u.target.Text()); ok {
		u.openPortScanFor(strings.TrimSpace(u.target.Text()), "")
		return
	}

	d := &scanOptionsUI{}
	dlg := newFloatingDialog()
	dlg.SetWindowTitle("Scan options · " + target)
	dlg.Resize(520, 720)
	v := qt.NewQVBoxLayout(dlg.QWidget)
	v.SetSpacing(8)

	// Target + hops.
	top := qt.NewQFormLayout2()
	d.domain = qt.NewQLineEdit2()
	d.domain.SetText(target)
	d.maxHops = qt.NewQSpinBox2()
	d.maxHops.SetRange(1, 100)
	d.maxHops.SetValue(u.maxHops.Value())
	top.AddRow3("Domain", d.domain.QWidget)
	top.AddRow3("Max hops", d.maxHops.QWidget)
	v.AddLayout(top.QLayout)

	// Presets.
	presets := qt.NewQWidget2()
	ph := qt.NewQHBoxLayout(presets)
	ph.SetContentsMargins(0, 0, 0, 0)
	ph.AddWidget(qt.NewQLabel3("Presets:").QWidget)
	ph.AddWidget(newButton("Basic", func() { d.apply(scanBasic()) }).QWidget)
	ph.AddWidget(newButton("Standard", func() { d.apply(scanStandard()) }).QWidget)
	ph.AddWidget(newButton("Deep", func() { d.apply(scanDeep()) }).QWidget)
	ph.AddStretch()
	v.AddWidget(presets)

	// DNS records.
	dns := qt.NewQGroupBox3("DNS records")
	dl := qt.NewQVBoxLayout(dns.QWidget)
	d.expandNS = qt.NewQCheckBox3("Follow nameservers (NS / SOA primary)")
	d.expandNS.SetChecked(true)
	dl.AddWidget(optionRow(d.expandNS, "Recursively expand NS and the SOA primary nameserver"))
	v.AddWidget(dns.QWidget)

	// Subdomain discovery.
	subs := qt.NewQGroupBox3("Subdomain discovery")
	sl := qt.NewQVBoxLayout(subs.QWidget)
	d.brute = qt.NewQCheckBox3("Brute force · 1000 common names")
	sl.AddWidget(optionRow(d.brute, "Probe the embedded list of common subdomain labels"))

	d.wordlist = qt.NewQLineEdit2()
	d.wordlist.SetPlaceholderText("embedded 1000-name list (optional custom file)")
	browse := newButton("Browse…", func() { u.pickWordlist(d.wordlist) })
	d.wordlistRow = qt.NewQWidget2()
	wh := qt.NewQHBoxLayout(d.wordlistRow)
	wh.SetContentsMargins(0, 0, 0, 0)
	wh.AddWidget(d.wordlist.QWidget)
	wh.AddWidget(browse.QWidget)
	sl.AddWidget(d.wordlistRow)

	d.ptr = qt.NewQCheckBox3("Reverse DNS (PTR)")
	sl.AddWidget(optionRow(d.ptr, "Resolve discovered IPs back to in-domain names"))
	d.sweep = qt.NewQCheckBox3("Sweep /24 netblocks")
	sl.AddWidget(optionRow(d.sweep, "Reverse-resolve the whole /24 around each IPv4 (slow)"))
	d.services = qt.NewQCheckBox3("Services (SPF / DMARC / SRV)")
	sl.AddWidget(optionRow(d.services, "Extract hostnames from TXT and SRV records"))

	d.subConcurrency = qt.NewQSpinBox2()
	d.subConcurrency.SetRange(1, 512)
	d.subConcurrency.SetValue(48)
	d.subRate = qt.NewQSpinBox2()
	d.subRate.SetRange(1, 1000)
	d.subRate.SetValue(50)
	pacing := qt.NewQWidget2()
	pacingH := qt.NewQHBoxLayout(pacing)
	pacingH.SetContentsMargins(0, 0, 0, 0)
	pacingH.SetSpacing(6)
	pacingH.AddWidget(qt.NewQLabel3("Parallel").QWidget)
	pacingH.AddWidget(d.subConcurrency.QWidget)
	pacingH.AddWidget(qt.NewQLabel3("lookups ·").QWidget)
	pacingH.AddWidget(d.subRate.QWidget)
	pacingH.AddWidget(qt.NewQLabel3("lookups/s").QWidget)
	pacingH.AddStretch()
	sl.AddWidget(pacing)
	v.AddWidget(subs.QWidget)

	// Web crawl.
	crawlBox := qt.NewQGroupBox3("Web crawl")
	cl := qt.NewQVBoxLayout(crawlBox.QWidget)
	d.crawl = qt.NewQCheckBox3("Frontpage + 1 level")
	cl.AddWidget(optionRow(d.crawl, "Fetch homepage + links with a browser agent, plus robots.txt and sitemap.xml"))
	d.crawlPages = qt.NewQSpinBox2()
	d.crawlPages.SetRange(1, 200)
	d.crawlPages.SetValue(25)
	d.crawlRow = qt.NewQWidget2()
	ch := qt.NewQHBoxLayout(d.crawlRow)
	ch.SetContentsMargins(0, 0, 0, 0)
	ch.AddWidget(qt.NewQLabel3("Max pages").QWidget)
	ch.AddWidget(d.crawlPages.QWidget)
	ch.AddStretch()
	cl.AddWidget(d.crawlRow)
	v.AddWidget(crawlBox.QWidget)

	// Targets.
	targetsBox := qt.NewQGroupBox3("Targets")
	tl := qt.NewQVBoxLayout(targetsBox.QWidget)
	d.review = qt.NewQRadioButton3("Review and pick")
	d.auto = qt.NewQRadioButton3("Auto-trace")
	reviewRow := qt.NewQWidget2()
	rh := qt.NewQHBoxLayout(reviewRow)
	rh.SetContentsMargins(0, 0, 0, 0)
	rh.AddWidget(d.review.QWidget)
	tl.AddWidget(reviewRow)
	autoRow := qt.NewQWidget2()
	ah := qt.NewQHBoxLayout(autoRow)
	ah.SetContentsMargins(0, 0, 0, 0)
	ah.AddWidget(d.auto.QWidget)
	tl.AddWidget(autoRow)
	d.maxTargets = qt.NewQSpinBox2()
	d.maxTargets.SetRange(1, 200)
	d.maxTargets.SetValue(24)
	capRow := qt.NewQWidget2()
	chh := qt.NewQHBoxLayout(capRow)
	chh.SetContentsMargins(0, 0, 0, 0)
	chh.AddWidget(qt.NewQLabel3("Max targets").QWidget)
	chh.AddWidget(d.maxTargets.QWidget)
	chh.AddStretch()
	tl.AddWidget(capRow)
	v.AddWidget(targetsBox.QWidget)

	v.AddStretch()

	// Footer.
	footer := qt.NewQWidget2()
	fh := qt.NewQHBoxLayout(footer)
	fh.SetContentsMargins(0, 0, 0, 0)
	fh.AddStretch()
	fh.AddWidget(newButton("Cancel", func() { dlg.Reject() }).QWidget)
	start := newButton("Start scan", nil)
	start.OnClicked(func() {
		opts := d.options()
		domain := cleanDomain(d.domain.Text())
		if domain == "" {
			return
		}
		dlg.Accept()
		u.resetForOperation()
		u.lastMaxHops = d.maxHops.Value()
		u.startOp("scan " + domain)
		for _, c := range []string{"dns", "subdomains", "crawl", "trace"} {
			u.openChannel(c)
		}
		go func() {
			err := u.app.Scan(ScanRequest{Domain: domain, MaxHops: d.maxHops.Value(), Options: opts})
			u.afterOp(err)
		}()
	})
	fh.AddWidget(start.QWidget)
	v.AddWidget(footer)

	// Keep dependent rows in sync with their toggles.
	d.brute.OnToggled(func(bool) { d.syncVisibility() })
	d.crawl.OnToggled(func(bool) { d.syncVisibility() })

	d.apply(scanStandard())
	dlg.Exec()
}

func (d *scanOptionsUI) apply(o ScanOptions, maxHops int) {
	d.expandNS.SetChecked(o.ExpandNS)
	d.brute.SetChecked(o.BruteForce)
	d.ptr.SetChecked(o.PTR)
	d.sweep.SetChecked(o.Sweep24)
	d.services.SetChecked(o.Services)
	d.crawl.SetChecked(o.Crawl)
	d.review.SetChecked(!o.AutoTrace)
	d.auto.SetChecked(o.AutoTrace)
	if o.WordlistPath != "" {
		d.wordlist.SetText(o.WordlistPath)
	}
	if o.CrawlMaxPages > 0 {
		d.crawlPages.SetValue(o.CrawlMaxPages)
	}
	if o.MaxTargets > 0 {
		d.maxTargets.SetValue(o.MaxTargets)
	}
	if o.SubdomainConcurrency > 0 {
		d.subConcurrency.SetValue(o.SubdomainConcurrency)
	}
	if o.SubdomainRate > 0 {
		d.subRate.SetValue(o.SubdomainRate)
	}
	d.maxHops.SetValue(maxHops)
	d.syncVisibility()
}

func (d *scanOptionsUI) options() ScanOptions {
	return ScanOptions{
		ExpandNS:             d.expandNS.IsChecked(),
		BruteForce:           d.brute.IsChecked(),
		WordlistPath:         strings.TrimSpace(d.wordlist.Text()),
		PTR:                  d.ptr.IsChecked(),
		Sweep24:              d.sweep.IsChecked(),
		Services:             d.services.IsChecked(),
		Crawl:                d.crawl.IsChecked(),
		CrawlMaxPages:        d.crawlPages.Value(),
		AutoTrace:            d.auto.IsChecked(),
		MaxTargets:           d.maxTargets.Value(),
		SubdomainConcurrency: d.subConcurrency.Value(),
		SubdomainRate:        d.subRate.Value(),
	}
}

func (d *scanOptionsUI) syncVisibility() {
	if d.brute.IsChecked() {
		d.wordlistRow.Show()
	} else {
		d.wordlistRow.Hide()
	}
	if d.crawl.IsChecked() {
		d.crawlRow.Show()
	} else {
		d.crawlRow.Hide()
	}
}

// optionRow wraps a checkbox with a small wrapped hint label beneath it.
func optionRow(cb *qt.QCheckBox, hint string) *qt.QWidget {
	box := qt.NewQWidget2()
	v := qt.NewQVBoxLayout(box)
	v.SetContentsMargins(0, 2, 0, 2)
	v.SetSpacing(0)
	v.AddWidget(cb.QWidget)
	label := qt.NewQLabel5(hint, box)
	label.SetWordWrap(true)
	v.AddWidget(label.QWidget)
	return box
}

func (u *uiApp) pickWordlist(edit *qt.QLineEdit) {
	path, err := u.app.PickWordlist()
	if err != nil || path == "" {
		return
	}
	edit.SetText(path)
}

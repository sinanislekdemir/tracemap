package domaincheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeResolver serves canned DNS answers.
type fakeResolver struct {
	ips  map[string][]net.IP
	cns  map[string]string
	mxs  map[string][]*net.MX
	nss  map[string][]*net.NS
	txts map[string][]string
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	return f.ips[host], nil
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return f.cns[host], nil
}

func (f fakeResolver) LookupMX(_ context.Context, host string) ([]*net.MX, error) {
	return f.mxs[host], nil
}

func (f fakeResolver) LookupNS(_ context.Context, host string) ([]*net.NS, error) {
	return f.nss[host], nil
}

func (f fakeResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	return f.txts[host], nil
}

// fakeRaw serves canned raw answers by qtype.
type fakeRaw struct {
	answers map[uint16][]RawAnswer
}

func (f fakeRaw) Query(_ context.Context, _ string, qtype uint16) ([]RawAnswer, error) {
	return f.answers[qtype], nil
}

// scriptedDialer answers WHOIS connections with canned bodies keyed by address.
type scriptedDialer struct {
	bodies map[string]string
}

func (d scriptedDialer) dial(_ context.Context, _, address string) (net.Conn, error) {
	client, server := net.Pipe()
	body := d.bodies[address]
	go func() {
		reader := bufio.NewReader(server)
		_, _ = reader.ReadString('\n')
		_, _ = server.Write([]byte(body))
		_ = server.Close()
	}()
	return client, nil
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM":            "example.com",
		"https://example.com/x":  "example.com",
		"http://example.com:443": "example.com",
		"example.com.":           "example.com",
		"  example.com  ":        "example.com",
	}
	for input, want := range cases {
		if got := NormalizeDomain(input); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseWhoisExtractsFields(t *testing.T) {
	body := `
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 2001-02-15T00:00:00Z
Registry Expiry Date: 2030-02-15T00:00:00Z
Updated Date: 2023-01-01T00:00:00Z
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: signedDelegation
Registrant Organization: Example Org
Registrant Country: US
`
	reg := parseWhois("example.com", body)
	if !strings.Contains(reg.Registrar, "Example Registrar") {
		t.Errorf("registrar = %q", reg.Registrar)
	}
	if reg.CreatedAt == 0 || reg.ExpiresAt == 0 {
		t.Errorf("dates not parsed: %+v", reg)
	}
	if len(reg.Statuses) != 1 || len(reg.Nameservers) != 2 {
		t.Errorf("statuses/nameservers = %+v / %+v", reg.Statuses, reg.Nameservers)
	}
	if reg.DNSSEC != "signed" {
		t.Errorf("dnssec = %q", reg.DNSSEC)
	}
	if reg.Registrant != "Example Org" || reg.Country != "US" {
		t.Errorf("registrant = %q / %q", reg.Registrant, reg.Country)
	}
}

func TestWhoisRegistrationFollowsRefer(t *testing.T) {
	analyzer := NewAnalyzerWithOptions(Options{
		Dial: scriptedDialer{bodies: map[string]string{
			"whois.iana.org:43":              "refer: whois.example-registry.test\n",
			"whois.example-registry.test:43": "Domain Name: EXAMPLE.TEST\nCreation Date: 2010-01-01\n",
		}}.dial,
	})
	reg, found, err := analyzer.whoisRegistration(context.Background(), "example.test")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if reg.Source != "whois" || reg.CreatedAt == 0 {
		t.Errorf("unexpected registration: %+v", reg)
	}
}

func TestWhoisNotFound(t *testing.T) {
	analyzer := NewAnalyzerWithOptions(Options{
		Dial: scriptedDialer{bodies: map[string]string{
			"whois.iana.org:43":              "refer: whois.example-registry.test\n",
			"whois.example-registry.test:43": "No match for \"EXAMPLE.TEST\"\n",
		}}.dial,
	})
	_, found, err := analyzer.whoisRegistration(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if found {
		t.Error("expected not found")
	}
}

func TestRDAPRegistration(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/dns.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"services":[[["test"],["` + server.URL + `/rdap/"]]]}`))
	})
	mux.HandleFunc("/rdap/domain/example.test", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"ldhName":"example.test",
			"status":["client transfer prohibited"],
			"events":[
				{"eventAction":"registration","eventDate":"2012-03-04T00:00:00Z"},
				{"eventAction":"expiration","eventDate":"2030-03-04T00:00:00Z"},
				{"eventAction":"last changed","eventDate":"2024-01-01T00:00:00Z"}
			],
			"nameservers":[{"ldhName":"ns1.example.test"},{"ldhName":"ns2.example.test"}],
			"secureDNS":{"delegationSigned":true},
			"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Example Registrar"]]]}]
		}`))
	})

	analyzer := NewAnalyzerWithOptions(Options{
		HTTPClient:   server.Client(),
		BootstrapURL: server.URL + "/dns.json",
	})
	reg, found, err := analyzer.rdapRegistration(context.Background(), "example.test")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if reg.Registrar != "Example Registrar" || reg.DNSSEC != "signed" {
		t.Errorf("registrar/dnssec = %q / %q", reg.Registrar, reg.DNSSEC)
	}
	if reg.CreatedAt == 0 || len(reg.Nameservers) != 2 {
		t.Errorf("unexpected registration: %+v", reg)
	}
}

func TestDNSReport(t *testing.T) {
	resolver := fakeResolver{
		ips: map[string][]net.IP{"example.test": {net.ParseIP("203.0.113.10")}},
		nss: map[string][]*net.NS{"example.test": {{Host: "ns1.example.test."}, {Host: "ns2.example.test."}}},
		mxs: map[string][]*net.MX{"example.test": {{Host: "mail.example.test.", Pref: 10}}},
		txts: map[string][]string{
			"example.test":                    {"v=spf1 include:_spf.example.test -all"},
			"_dmarc.example.test":             {"v=DMARC1; p=reject; rua=mailto:dmarc@example.test"},
			"default._domainkey.example.test": {"v=DKIM1; p=MIGfMA0GCSqGSIb3"},
			"_mta-sts.example.test":           {"v=STSv1; id=1"},
			"_smtp._tls.example.test":         {"v=TLSRPTv1; rua=mailto:tls@example.test"},
		},
	}
	raw := fakeRaw{answers: map[uint16][]RawAnswer{
		typeCAA:    {{Type: typeCAA, Data: append([]byte{0, 5}, []byte("issueletsencrypt.org")...)}},
		typeDNSKEY: {{Type: typeDNSKEY}},
		typeDS:     {{Type: typeDS}},
	}}
	analyzer := NewAnalyzerWithOptions(Options{Resolver: resolver, Raw: raw})

	report := analyzer.dnsReport(context.Background(), "example.test")
	if len(report.Addresses) != 1 || len(report.Nameservers) != 2 || len(report.MX) != 1 {
		t.Errorf("addresses/ns/mx = %+v/%+v/%+v", report.Addresses, report.Nameservers, report.MX)
	}
	if len(report.SPF) != 1 || report.SPFPolicy != "fail" || report.SPFLookups != 1 {
		t.Errorf("spf = %+v policy=%q lookups=%d", report.SPF, report.SPFPolicy, report.SPFLookups)
	}
	if report.DMARCPolicy != "reject" || len(report.DMARCRUA) != 1 {
		t.Errorf("dmarc = %+v policy=%q", report.DMARC, report.DMARCPolicy)
	}
	if len(report.DKIM) != 1 || len(report.CAA) != 1 {
		t.Errorf("dkim/caa = %+v / %+v", report.DKIM, report.CAA)
	}
	if !report.DNSKEY || !report.DS {
		t.Errorf("dnssec = %v/%v", report.DNSKEY, report.DS)
	}
}

func TestWebReportTLS(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	analyzer := NewAnalyzerWithOptions(Options{HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})

	report := analyzer.webReport(context.Background(), "example.test")
	if !report.HTTPS {
		t.Fatalf("expected HTTPS, got %+v", report)
	}
	if report.CertNotAfter == 0 || report.TLSVersion == "" {
		t.Errorf("cert/tls missing: %+v", report)
	}
	if report.Headers["strict-transport-security"] == "" {
		t.Errorf("hsts header missing: %+v", report.Headers)
	}
}

func TestWebReportRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.test/", http.StatusMovedPermanently)
	}))
	defer server.Close()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	analyzer := NewAnalyzerWithOptions(Options{HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})

	report := analyzer.webReport(context.Background(), "example.test")
	if !report.RedirectsHTTPS {
		t.Errorf("expected HTTPS redirect, got %+v", report)
	}
}

func TestScoreAndChecks(t *testing.T) {
	report := Report{
		Registration: &Registration{Found: true, AgeDays: 4000, ExpiresAt: time.Now().Add(400 * 24 * time.Hour).UnixMilli(), DNSSEC: "signed", Nameservers: []string{"a", "b"}, Registrar: "R"},
		DNS: DNSReport{
			Addresses: []string{"203.0.113.10"},
			CAA:       []string{"0 issue letsencrypt.org"},
			DNSKEY:    true, DS: true,
			SPF: []string{"v=spf1 -all"}, SPFPolicy: "fail", SPFLookups: 1,
			DMARC: []string{"v=DMARC1; p=reject"}, DMARCPolicy: "reject", DKIM: []string{"default"},
		},
		Web: WebReport{HTTPS: true, RedirectsHTTPS: true, CertNotAfter: time.Now().Add(200 * 24 * time.Hour).UnixMilli(), CertIssuer: "CA", Headers: map[string]string{
			"strict-transport-security": "max-age=31536000",
			"content-security-policy":   "default-src 'self'",
			"x-content-type-options":    "nosniff",
			"x-frame-options":           "DENY",
		}},
	}
	checks := buildChecks(&report)
	value, grade := score(checks)
	if value < 90 || grade != "A" {
		t.Errorf("score=%d grade=%s", value, grade)
	}

	bad := Report{}
	badChecks := buildChecks(&bad)
	badScore, badGrade := score(badChecks)
	if badScore > 40 || badGrade != "F" {
		t.Errorf("bad score=%d grade=%s", badScore, badGrade)
	}
	if len(badChecks) == 0 {
		t.Error("expected checks for an empty report")
	}
}

func TestSPFAndHSTSHelpers(t *testing.T) {
	if got := spfPolicy("v=spf1 include:a -all"); got != "fail" {
		t.Errorf("spfPolicy = %q", got)
	}
	if got := spfLookupCount("v=spf1 include:a include:b mx a:host -all"); got != 4 {
		t.Errorf("spfLookupCount = %d", got)
	}
	if age, ok := hstsMaxAge("max-age=63072000; includeSubDomains"); !ok || age != 63072000 {
		t.Errorf("hstsMaxAge = %d,%v", age, ok)
	}
	if got := formatCAA(append([]byte{0, 5}, []byte("issueletsencrypt.org")...)); got != "0 issue letsencrypt.org" {
		t.Errorf("formatCAA = %q", got)
	}
}

package portscan

import "testing"

func TestIdentifyUDP(t *testing.T) {
	dns := make([]byte, 12)
	dns[2] = 0x80 // QR bit set
	if product, _, _ := identifyUDP(53, dns); product != "DNS" {
		t.Errorf("DNS response product = %q, want DNS", product)
	}
	if product, _, _ := identifyUDP(5353, dns); product != "mDNS" {
		t.Errorf("mDNS response product = %q, want mDNS", product)
	}
	if product, _, _ := identifyUDP(123, make([]byte, 48)); product != "NTP" {
		t.Errorf("NTP response product = %q, want NTP", product)
	}
	if _, _, banner := identifyUDP(9999, []byte("hello udp service")); banner == "" {
		t.Error("expected a printable banner for a text reply")
	}
	if _, _, banner := identifyUDP(9999, []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe}); banner != "" {
		t.Errorf("opaque binary should not produce a banner, got %q", banner)
	}
}

func TestIsDNSResponse(t *testing.T) {
	if isDNSResponse([]byte{0, 0}) {
		t.Error("short payload should not be a DNS response")
	}
	dns := make([]byte, 12)
	if isDNSResponse(dns) {
		t.Error("query (QR clear) should not be a DNS response")
	}
	dns[2] = 0x80
	if !isDNSResponse(dns) {
		t.Error("QR set should be a DNS response")
	}
}

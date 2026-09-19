package portscan

// udpProbePayload returns a small, protocol-appropriate datagram for known UDP
// services so they reply, or nil to send a bare datagram. UDP scanning is
// inherently best-effort: without raw ICMP a filtered port is indistinguishable
// from a closed one, so only replies are reported.
func udpProbePayload(port int) []byte {
	switch port {
	case 53:
		// Minimal recursive DNS query for the root NS records.
		return []byte{
			0x00, 0x00, // transaction id
			0x01, 0x00, // flags: recursion desired
			0x00, 0x01, // questions
			0x00, 0x00, // answers
			0x00, 0x00, // authority
			0x00, 0x00, // additional
			0x00,       // root name
			0x00, 0x02, // type NS
			0x00, 0x01, // class IN
		}
	case 123:
		// NTP client request: 48 bytes, first byte LI=0 VN=3 Mode=3.
		buf := make([]byte, 48)
		buf[0] = 0x1b
		return buf
	default:
		return nil
	}
}

// identifyUDP labels a UDP reply. Known services are recognised from the reply
// shape; any other reply with enough printable content is kept as a banner.
func identifyUDP(port int, payload []byte) (product, detail, banner string) {
	switch port {
	case 53:
		if isDNSResponse(payload) {
			return "DNS", "dns response", ""
		}
	case 5353:
		if isDNSResponse(payload) {
			return "mDNS", "mdns response", ""
		}
	case 123:
		if len(payload) >= 48 {
			return "NTP", "ntp response", ""
		}
	}
	if hasPrintable(payload) {
		return "", "", sanitizeBanner(payload)
	}
	return "", "", ""
}

// isDNSResponse reports whether payload looks like a DNS message with the QR
// (response) bit set.
func isDNSResponse(payload []byte) bool {
	return len(payload) >= 12 && payload[2]&0x80 != 0
}

// hasPrintable reports whether payload is mostly printable text, so opaque
// binary replies are not surfaced as a misleading banner.
func hasPrintable(payload []byte) bool {
	printable := 0
	for _, c := range payload {
		if c == '\r' || c == '\n' || c == '\t' || (c >= 32 && c < 127) {
			printable++
		}
	}
	return printable >= 4 && printable*2 >= len(payload)
}

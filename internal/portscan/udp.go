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

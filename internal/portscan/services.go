package portscan

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// serviceNames maps well-known and common ports to a short service name. It is
// a curated local table (no external lookup) used to label open ports.
var serviceNames = map[int]string{
	7: "echo", 9: "discard", 13: "daytime", 19: "chargen", 20: "ftp-data",
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time",
	42: "nameserver", 43: "whois", 49: "tacacs", 53: "dns", 67: "dhcp",
	68: "dhcp", 69: "tftp", 70: "gopher", 79: "finger", 80: "http",
	88: "kerberos", 102: "iso-tsap", 110: "pop3", 111: "rpcbind", 113: "ident",
	119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 177: "xdmcp",
	179: "bgp", 194: "irc", 201: "apple-rtmp", 389: "ldap", 427: "svrloc",
	443: "https", 444: "snpp", 445: "microsoft-ds", 464: "kpasswd", 465: "smtps",
	500: "isakmp", 512: "exec", 513: "login", 514: "syslog", 515: "printer",
	520: "rip", 521: "ripng", 540: "uucp", 548: "afp", 554: "rtsp",
	587: "submission", 623: "asf-rmcp", 631: "ipp", 636: "ldaps", 646: "ldp",
	873: "rsync", 902: "vmware", 990: "ftps", 993: "imaps", 995: "pop3s",
	1025: "nfs-or-iis", 1026: "win-rpc", 1080: "socks", 1194: "openvpn",
	1433: "ms-sql", 1434: "ms-sql-m", 1521: "oracle", 1701: "l2tp",
	1723: "pptp", 1883: "mqtt", 1900: "ssdp", 2049: "nfs", 2082: "cpanel",
	2083: "cpanel-ssl", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
	2376: "docker-ssl", 2379: "etcd", 2480: "orientdb", 3000: "dev-http",
	3128: "squid", 3260: "iscsi", 3306: "mysql", 3389: "rdp", 3690: "svn",
	4000: "icq", 4333: "msql", 4444: "krb524", 4567: "sinatra", 5000: "upnp",
	5060: "sip", 5061: "sips", 5222: "xmpp", 5269: "xmpp-server",
	5353: "mdns", 5432: "postgres", 5555: "adb", 5601: "kibana",
	5672: "amqp", 5900: "vnc", 5938: "teamviewer", 5984: "couchdb",
	6000: "x11", 6379: "redis", 6443: "kubernetes", 6667: "irc",
	7001: "weblogic", 7077: "spark", 8000: "http-alt", 8008: "http-alt",
	8009: "ajp", 8080: "http-proxy", 8081: "http-alt", 8086: "influxdb",
	8088: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
	9001: "tor-orport", 9042: "cassandra", 9092: "kafka", 9100: "jetdirect",
	9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
	9999: "http-alt", 10000: "webmin", 11211: "memcached",
	15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb", 50000: "sap",
	50070: "hadoop", 61616: "activemq",
}

// commonOrder lists frequently open ports, roughly most to least common. It
// seeds the preset port sets.
var commonOrder = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
	8443, 8888, 8000, 8008, 8081, 8088, 9000, 9090, 9200, 9300,
	11211, 27017, 6379, 5432, 1433, 1521, 2049, 2375, 2376, 3000,
	5000, 5060, 5222, 5353, 5672, 6443, 7001, 8009, 8086, 9001,
	9042, 9092, 9100, 9418, 15672, 27018, 50000, 50070, 61616, 2379,
	2181, 5984, 5601, 3128, 1883, 1900, 1194, 1701, 873, 631,
	548, 554, 587, 636, 646, 902, 990, 1025, 1026, 1080,
	1434, 2082, 2083, 2222, 3260, 3690, 4000, 4333, 4444, 4567,
	5061, 5269, 5555, 5938, 6000, 6667, 7077, 9999, 10000, 161,
	162, 389, 427, 464, 500, 512, 513, 514, 515, 520,
	521, 540, 67, 68, 69, 70, 79, 88, 102, 113,
	119, 123, 137, 138, 177, 179, 194, 201, 444, 7,
}

// Preset port sets exposed to the UI. Top1000 is the well-known range 1-1024
// merged with the common high ports above.
var (
	// Top20 is the 20 most commonly open ports.
	Top20 = firstN(commonOrder, 20)
	// Top100 is the 100 most commonly open ports.
	Top100 = firstN(commonOrder, 100)
	// Top1000 is the well-known range plus common high ports.
	Top1000 = wellKnown()
)

// MaxPorts bounds how many ports a single scan may target.
const MaxPorts = 65535

// PresetPorts returns the port list for a named preset. Recognised names are
// "top20", "top100" and "top1000"; an empty name defaults to "top100".
func PresetPorts(preset string) ([]int, error) {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "", "top100":
		return clonePorts(Top100), nil
	case "top20":
		return clonePorts(Top20), nil
	case "top1000":
		return clonePorts(Top1000), nil
	default:
		return nil, fmt.Errorf("unknown preset %q", preset)
	}
}

// ParsePorts parses a port specification of single ports, ranges, or both,
// separated by commas (for example "22,80,443-445"). Ports are returned sorted
// and deduplicated.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("no ports specified")
	}

	set := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if from, to, ok := strings.Cut(part, "-"); ok {
			start, err := parsePort(from)
			if err != nil {
				return nil, err
			}
			end, err := parsePort(to)
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if end-start+1 > MaxPorts {
				return nil, fmt.Errorf("port range %q is too large", part)
			}
			for port := start; port <= end; port++ {
				set[port] = struct{}{}
			}
			continue
		}
		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		set[port] = struct{}{}
	}

	if len(set) == 0 {
		return nil, errors.New("no ports specified")
	}
	return sortedKeys(set), nil
}

// ServiceName returns the well-known service name for a port, or "".
func ServiceName(port int) string {
	return serviceNames[port]
}

// parsePort parses and validates a single port number.
func parsePort(value string) (int, error) {
	value = strings.TrimSpace(value)
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d out of range", port)
	}
	return port, nil
}

// firstN returns a copy of the first n entries of ports (or all of them).
func firstN(ports []int, n int) []int {
	if n > len(ports) {
		n = len(ports)
	}
	return clonePorts(ports[:n])
}

// wellKnown merges ports 1-1024 with commonOrder, sorted and deduplicated.
func wellKnown() []int {
	set := make(map[int]struct{}, 1024+len(commonOrder))
	for port := 1; port <= 1024; port++ {
		set[port] = struct{}{}
	}
	for _, port := range commonOrder {
		set[port] = struct{}{}
	}
	return sortedKeys(set)
}

// sortedKeys returns the keys of set in ascending order.
func sortedKeys(set map[int]struct{}) []int {
	out := make([]int, 0, len(set))
	for port := range set {
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

// clonePorts returns a copy of ports so callers cannot mutate the presets.
func clonePorts(ports []int) []int {
	out := make([]int, len(ports))
	copy(out, ports)
	return out
}

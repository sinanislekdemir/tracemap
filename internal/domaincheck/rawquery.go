package domaincheck

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNS record types not exposed by net.Resolver.
const (
	typeDS     uint16 = 43
	typeDNSKEY uint16 = 48
	typeCAA    uint16 = 257
)

// RawAnswer is one raw DNS answer.
type RawAnswer struct {
	Type uint16
	Data []byte
}

// RawQueryer sends an arbitrary DNS query. It exists so CAA, DNSKEY and DS
// records (which net.Resolver cannot fetch) can be read, and so tests can fake
// the network.
type RawQueryer interface {
	Query(ctx context.Context, name string, qtype uint16) ([]RawAnswer, error)
}

// systemQueryer sends UDP queries to the host's configured resolver.
type systemQueryer struct {
	dial    DialFunc
	timeout time.Duration

	mu     sync.Mutex
	server string
}

func newSystemQueryer(dial DialFunc, timeout time.Duration) *systemQueryer {
	return &systemQueryer{dial: dial, timeout: timeout}
}

func (q *systemQueryer) Query(ctx context.Context, name string, qtype uint16) ([]RawAnswer, error) {
	server, err := q.serverAddress(ctx, name)
	if err != nil {
		return nil, err
	}

	question, err := dnsmessage.NewName(fqdn(name))
	if err != nil {
		return nil, err
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: question, Type: dnsmessage.Type(qtype), Class: dnsmessage.ClassINET}},
	}
	packed, err := query.Pack()
	if err != nil {
		return nil, err
	}

	conn, err := q.dial(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(q.timeout))

	if _, err := conn.Write(packed); err != nil {
		return nil, err
	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	var response dnsmessage.Message
	if err := response.Unpack(buffer[:n]); err != nil {
		return nil, err
	}
	answers := make([]RawAnswer, 0, len(response.Answers))
	for _, answer := range response.Answers {
		raw := RawAnswer{Type: uint16(answer.Header.Type)}
		if unknown, ok := answer.Body.(*dnsmessage.UnknownResource); ok {
			raw.Data = unknown.Data
		}
		answers = append(answers, raw)
	}
	return answers, nil
}

// serverAddress discovers the configured resolver by observing the address the
// pure-Go resolver dials, caching the result.
func (q *systemQueryer) serverAddress(ctx context.Context, name string) (string, error) {
	q.mu.Lock()
	if q.server != "" {
		server := q.server
		q.mu.Unlock()
		return server, nil
	}
	q.mu.Unlock()

	var server string
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if server == "" {
			server = address
		}
		return q.dial(ctx, network, address)
	}}
	_, _ = resolver.LookupNS(ctx, name)
	if server == "" {
		return "", errors.New("domaincheck: could not determine DNS server")
	}

	q.mu.Lock()
	q.server = server
	q.mu.Unlock()
	return server, nil
}

// queryCAA returns the formatted CAA records for a domain.
func (a *Analyzer) queryCAA(ctx context.Context, domain string) []string {
	answers, err := a.raw.Query(ctx, domain, typeCAA)
	if err != nil {
		return nil
	}
	var out []string
	for _, answer := range answers {
		if answer.Type != typeCAA {
			continue
		}
		if formatted := formatCAA(answer.Data); formatted != "" {
			out = append(out, formatted)
		}
	}
	return dedupe(out)
}

// queryHasType reports whether a record of the given type exists for name.
func (a *Analyzer) queryHasType(ctx context.Context, name string, qtype uint16) bool {
	answers, err := a.raw.Query(ctx, name, qtype)
	if err != nil {
		return false
	}
	for _, answer := range answers {
		if answer.Type == qtype {
			return true
		}
	}
	return false
}

// formatCAA renders CAA rdata (flags, tag length, tag, value).
func formatCAA(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	flags := data[0]
	tagLen := int(data[1])
	if len(data) < 2+tagLen {
		return ""
	}
	tag := string(data[2 : 2+tagLen])
	value := string(data[2+tagLen:])
	return strings.TrimSpace(strconv.Itoa(int(flags)) + " " + tag + " " + value)
}

// fqdn returns the absolute form of a DNS name.
func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

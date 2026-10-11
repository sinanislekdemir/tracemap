// Package ping performs ICMP echo ("ping") reachability checks over an
// unprivileged datagram socket, so a port scan can skip dead hosts before it
// starts. ICMP is best-effort by nature: a live host may still not answer
// (firewalled, or asked to ignore echo), which is why callers expose it as an
// option rather than a requirement.
package ping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ErrUnavailable reports that an ICMP socket could not be opened, usually
// because the platform requires privileges the process does not have.
var ErrUnavailable = errors.New("ICMP socket unavailable")

// ErrNoIPv4 reports that the host has no IPv4 address, so it cannot be probed
// with this (IPv4) pinger.
var ErrNoIPv4 = errors.New("host has no IPv4 address")

// ErrTimeout reports that no echo reply arrived before the deadline.
var ErrTimeout = errors.New("no ICMP reply")

// Pinger sends ICMP echo requests over one reusable, unprivileged socket. It is
// safe for concurrent use.
type Pinger struct {
	conn *icmp.PacketConn
	id   uint16

	mu      sync.Mutex
	seq     uint16
	waiters map[string][]chan struct{}

	closeOnce sync.Once
	done      chan struct{}
}

// Open opens the ICMP socket. It wraps ErrUnavailable when the platform refuses
// the socket (typically missing the CAP_NET_RAW privilege or an out-of-range
// net.ipv4.ping_group_range on Linux).
func Open() (*Pinger, error) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	p := &Pinger{
		conn:    conn,
		id:      uint16(os.Getpid() & 0xffff),
		waiters: make(map[string][]chan struct{}),
		done:    make(chan struct{}),
	}
	go p.readLoop()
	return p, nil
}

// Close releases the socket and stops the reader.
func (p *Pinger) Close() error {
	p.closeOnce.Do(func() { close(p.done) })
	return p.conn.Close()
}

// Ping sends one echo request to host and waits for its reply. It returns nil
// when the host answered, ErrTimeout when it did not, and ErrNoIPv4 when the
// host cannot be pinged over IPv4.
func (p *Pinger) Ping(ctx context.Context, host string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ip, err := resolveIPv4(ctx, host)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.seq++
	seq := p.seq
	key := replyKey(ip, seq)
	ch := make(chan struct{}, 1)
	p.waiters[key] = append(p.waiters[key], ch)
	p.mu.Unlock()
	defer p.removeWaiter(key, ch)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(p.id), Seq: int(seq), Data: []byte("tracemap")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := p.conn.WriteTo(wire, &net.UDPAddr{IP: ip}); err != nil {
		return err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-timer.C:
		return ErrTimeout
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return ErrUnavailable
	}
}

// readLoop dispatches echo replies to the waiters registered for their
// source address and sequence number.
func (p *Pinger) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, peer, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || msg.Type != icmp.Type(ipv4.ICMPTypeEchoReply) {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		addr, ok := peer.(*net.UDPAddr)
		if !ok {
			continue
		}
		p.signal(replyKey(addr.IP, uint16(echo.Seq)))
	}
}

// signal wakes every waiter registered for key.
func (p *Pinger) signal(key string) {
	p.mu.Lock()
	waiters := p.waiters[key]
	delete(p.waiters, key)
	p.mu.Unlock()
	for _, ch := range waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (p *Pinger) removeWaiter(key string, ch chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.waiters[key]
	for i, c := range list {
		if c == ch {
			p.waiters[key] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(p.waiters[key]) == 0 {
		delete(p.waiters, key)
	}
}

// replyKey identifies a reply by source address and sequence number. The ICMP
// identifier is not used: the kernel rewrites it to the socket's local port on
// an unprivileged datagram socket.
func replyKey(ip net.IP, seq uint16) string {
	return ip.String() + "|" + strconv.Itoa(int(seq))
}

// resolveIPv4 turns host into an IPv4 address, resolving it when necessary.
func resolveIPv4(ctx context.Context, host string) (net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, ErrNoIPv4
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, ErrNoIPv4
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, ErrNoIPv4
}

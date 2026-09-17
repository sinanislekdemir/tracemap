// Package netcat provides interactive, line-oriented TCP sessions in the spirit
// of netcat ("nc"), using only the Go standard library. A session is a single
// long-lived connection: the caller writes data with Send and receives whatever
// the peer sends through the Observer callbacks.
//
// It is deliberately not a terminal emulator. Data is delivered as raw bytes so
// the frontend can render binary-safe output, but there is no ANSI/PTY handling
// and no listen mode.
package netcat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Session tuning defaults.
const (
	// DefaultTimeout bounds how long a connection attempt may take.
	DefaultTimeout = 10 * time.Second
	// readChunk is the maximum number of bytes read from the peer per event.
	readChunk = 4096
)

// Options describes a connection to open.
type Options struct {
	// Host is a hostname or IP literal. Required.
	Host string
	// Port is the TCP port to connect to. Required, 1-65535.
	Port int
	// Timeout bounds the connection attempt (and TLS handshake). Defaults to
	// DefaultTimeout when zero.
	Timeout time.Duration
	// TLS wraps the connection in a TLS client handshake.
	TLS bool
	// ServerName overrides the SNI name for TLS. When empty the host is used
	// unless it is an IP literal.
	ServerName string
}

// Observer receives session events. Every callback is optional and may be
// invoked from the session's reader goroutine.
type Observer struct {
	// OnData is invoked with each chunk read from the peer. The slice is a
	// private copy and is safe to retain.
	OnData func(id string, data []byte)
	// OnClose is invoked exactly once when the session ends, with a
	// human-readable reason ("closed", "remote closed", "shutdown", or an
	// error string).
	OnClose func(id, reason string)
}

// Session is one live connection.
type Session struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	TLS    bool   `json:"tls"`
	Local  string `json:"local,omitempty"`
	Remote string `json:"remote,omitempty"`

	conn   net.Conn
	obs    Observer
	once   sync.Once
	closed atomic.Bool
}

// Manager owns the live sessions. Its zero value is not usable; call
// NewManager.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	seq      atomic.Uint64
}

// NewManager returns an empty session manager.
func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*Session)}
}

// Connect dials host:port and starts streaming the peer's output through obs.
// The returned session stays alive until Close, CloseAll, the peer disconnects,
// or a read error occurs.
func (m *Manager) Connect(ctx context.Context, opts Options, obs Observer) (*Session, error) {
	host := strings.TrimSpace(opts.Host)
	if host == "" {
		return nil, errors.New("host is required")
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return nil, fmt.Errorf("port %d out of range", opts.Port)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(opts.Port)))
	if err != nil {
		return nil, err
	}

	if opts.TLS {
		serverName := strings.TrimSpace(opts.ServerName)
		if serverName == "" && net.ParseIP(host) == nil {
			serverName = host
		}
		// InsecureSkipVerify is intentional: this is a diagnostic client that
		// identifies services, not one that establishes trust.
		tlsConn := tls.Client(conn, &tls.Config{ //nolint:gosec // identification only
			InsecureSkipVerify: true,
			ServerName:         serverName,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	session := &Session{
		ID:   "nc-" + strconv.FormatUint(m.seq.Add(1), 10),
		Host: host,
		Port: opts.Port,
		TLS:  opts.TLS,
		conn: conn,
		obs:  obs,
	}
	if addr := conn.LocalAddr(); addr != nil {
		session.Local = addr.String()
	}
	if addr := conn.RemoteAddr(); addr != nil {
		session.Remote = addr.String()
	}

	m.mu.Lock()
	m.sessions[session.ID] = session
	m.mu.Unlock()

	go m.readLoop(session)
	return session, nil
}

// Send writes data to the session's connection.
func (m *Manager) Send(id, data string) error {
	session, err := m.get(id)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(session.conn, data); err != nil {
		return err
	}
	return nil
}

// Close ends a session and notifies its observer. Closing an unknown session is
// not an error.
func (m *Manager) Close(id string) error {
	session, err := m.get(id)
	if err != nil {
		if errors.Is(err, errUnknownSession) {
			return nil
		}
		return err
	}
	m.close(session, "closed")
	return nil
}

// CloseAll ends every session, used on application shutdown.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()

	for _, session := range sessions {
		m.close(session, "shutdown")
	}
}

// readLoop streams the peer's output until the connection ends.
func (m *Manager) readLoop(session *Session) {
	buf := make([]byte, readChunk)
	for {
		n, err := session.conn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			if session.obs.OnData != nil {
				session.obs.OnData(session.ID, data)
			}
		}
		if err != nil {
			m.close(session, closeReason(err))
			return
		}
	}
}

// close tears down a session exactly once and removes it from the registry.
func (m *Manager) close(session *Session, reason string) {
	session.once.Do(func() {
		session.closed.Store(true)
		_ = session.conn.Close()

		m.mu.Lock()
		delete(m.sessions, session.ID)
		m.mu.Unlock()

		if session.obs.OnClose != nil {
			session.obs.OnClose(session.ID, reason)
		}
	})
}

// errUnknownSession distinguishes a missing session from other lookup errors.
var errUnknownSession = errors.New("unknown session")

// get returns a live session by id.
func (m *Manager) get(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w %q", errUnknownSession, id)
	}
	return session, nil
}

// closeReason maps a read error to a human-readable disconnect reason.
func closeReason(err error) string {
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return "remote closed"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	default:
		return err.Error()
	}
}

package netcat

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestConnectSendReceive(t *testing.T) {
	port, closeLn := echoServer(t)
	defer closeLn()

	data := make(chan string, 4)
	closed := make(chan string, 1)
	manager := NewManager()
	defer manager.CloseAll()

	session, err := manager.Connect(context.Background(), Options{
		Host: "127.0.0.1", Port: port, Timeout: time.Second,
	}, Observer{
		OnData:  func(_ string, b []byte) { data <- string(b) },
		OnClose: func(_, reason string) { closed <- reason },
	})
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}
	if session.ID == "" {
		t.Fatalf("session has no id")
	}

	if err := manager.Send(session.ID, "hello\n"); err != nil {
		t.Fatalf("Send error: %v", err)
	}
	if got := recv(t, data); got != "hello\n" {
		t.Fatalf("received %q, want %q", got, "hello\n")
	}

	if err := manager.Close(session.ID); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if got := recv(t, closed); got != "closed" {
		t.Fatalf("close reason = %q, want closed", got)
	}
}

func TestRemoteCloseReason(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	closed := make(chan string, 1)
	manager := NewManager()
	defer manager.CloseAll()

	if _, err := manager.Connect(context.Background(), Options{
		Host: "127.0.0.1", Port: portOf(ln.Addr()), Timeout: time.Second,
	}, Observer{OnClose: func(_, reason string) { closed <- reason }}); err != nil {
		t.Fatalf("Connect error: %v", err)
	}

	if got := recv(t, closed); got != "remote closed" {
		t.Fatalf("close reason = %q, want remote closed", got)
	}
}

func TestTLSConnect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure hello"))
	}))
	defer server.Close()

	host, port := hostPort(t, server.URL)
	data := make(chan string, 4)
	manager := NewManager()
	defer manager.CloseAll()

	session, err := manager.Connect(context.Background(), Options{
		Host: host, Port: port, Timeout: time.Second, TLS: true,
	}, Observer{OnData: func(_ string, b []byte) { data <- string(b) }})
	if err != nil {
		t.Fatalf("TLS Connect error: %v", err)
	}
	if !session.TLS {
		t.Errorf("session.TLS = false, want true")
	}

	if err := manager.Send(session.ID, "GET / HTTP/1.0\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatalf("Send error: %v", err)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case chunk := <-data:
			if strings.Contains(chunk, "secure hello") {
				return
			}
		case <-deadline:
			t.Fatalf("did not receive the TLS server response")
		}
	}
}

func TestConnectValidation(t *testing.T) {
	manager := NewManager()
	defer manager.CloseAll()

	if _, err := manager.Connect(context.Background(), Options{Host: "", Port: 80}, Observer{}); err == nil {
		t.Errorf("empty host should fail")
	}
	if _, err := manager.Connect(context.Background(), Options{Host: "127.0.0.1", Port: 0}, Observer{}); err == nil {
		t.Errorf("port 0 should fail")
	}
	if _, err := manager.Connect(context.Background(), Options{Host: "127.0.0.1", Port: 70000}, Observer{}); err == nil {
		t.Errorf("port 70000 should fail")
	}
}

func TestUnknownSession(t *testing.T) {
	manager := NewManager()
	defer manager.CloseAll()

	if err := manager.Send("nope", "x"); err == nil {
		t.Errorf("Send to unknown session should fail")
	}
	if err := manager.Close("nope"); err != nil {
		t.Errorf("Close of unknown session = %v, want nil", err)
	}
}

func TestConnectRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := portOf(ln.Addr())
	_ = ln.Close()

	manager := NewManager()
	defer manager.CloseAll()

	_, err = manager.Connect(context.Background(), Options{
		Host: "127.0.0.1", Port: port, Timeout: 300 * time.Millisecond,
	}, Observer{})
	if err == nil {
		t.Fatalf("Connect to a closed port should fail")
	}
}

// echoServer starts a TCP listener that echoes each read back to the client.
func echoServer(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						_, _ = conn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return portOf(ln.Addr()), func() { _ = ln.Close() }
}

func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for a value")
		return ""
	}
}

func portOf(addr net.Addr) int {
	return addr.(*net.TCPAddr).Port
}

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return parsed.Hostname(), port
}

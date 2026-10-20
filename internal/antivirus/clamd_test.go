package antivirus

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeClamd serves one behavior on a listener until the test ends.
func fakeClamd(t *testing.T, ln net.Listener, handle func(net.Conn)) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				handle(conn)
			}()
		}
	}()
}

// reply returns a handler that checks the PING command and writes answer.
func reply(t *testing.T, answer string) func(net.Conn) {
	t.Helper()
	return func(conn net.Conn) {
		buf := make([]byte, len(pingCommand))
		if _, err := io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, pingCommand) {
			t.Errorf("command = %q, %v", buf, err)
			return
		}
		_, _ = conn.Write([]byte(answer))
	}
}

func tcpListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestNewClientDefaultsAndOptions(t *testing.T) {
	c := NewClient("tcp", "clamav:3310")
	if c.network != "tcp" || c.address != "clamav:3310" || c.timeout != DefaultTimeout || c.dial == nil {
		t.Fatalf("defaults = %+v", c)
	}
	c = NewClient("tcp", "x", WithTimeout(0), WithTimeout(-1), WithDialer(nil))
	if c.timeout != DefaultTimeout || c.dial == nil {
		t.Fatalf("ignored options changed client: %+v", c)
	}
	called := false
	dial := func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("boom")
	}
	c = NewClient("tcp", "x", WithTimeout(time.Second), WithDialer(dial))
	if c.timeout != time.Second {
		t.Fatalf("timeout = %v", c.timeout)
	}
	if err := c.Ping(context.Background()); err == nil || !called {
		t.Fatalf("Ping with injected dialer = %v, called %v", err, called)
	}
}

func TestPing(t *testing.T) {
	tests := []struct {
		name    string
		answer  string
		wantErr error
	}{
		{"pong", "PONG\x00", nil},
		{"wrong reply", "PANG\x00", ErrUnexpectedReply},
		{"no terminator", "PONG", ErrUnexpectedReply},
		{"too long", string(bytes.Repeat([]byte("A"), maxReplyLen+10)), ErrUnexpectedReply},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := tcpListener(t)
			fakeClamd(t, ln, reply(t, tt.answer))
			err := NewClient("tcp", ln.Addr().String()).Ping(context.Background())
			if tt.wantErr == nil && err != nil {
				t.Fatalf("Ping = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("Ping = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestPingTimeout(t *testing.T) {
	ln := tcpListener(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fakeClamd(t, ln, func(net.Conn) { <-release })

	start := time.Now()
	err := NewClient("tcp", ln.Addr().String(), WithTimeout(100*time.Millisecond)).Ping(context.Background())
	if err == nil {
		t.Fatal("Ping succeeded against a silent server")
	}
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("Ping = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Ping took %v", d)
	}
}

func TestPingContextCanceled(t *testing.T) {
	ln := tcpListener(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	accepted := make(chan struct{})
	fakeClamd(t, ln, func(net.Conn) { close(accepted); <-release })

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-accepted; cancel() }()
	err := NewClient("tcp", ln.Addr().String(), WithTimeout(time.Minute)).Ping(ctx)
	if err == nil {
		t.Fatal("Ping succeeded after cancellation")
	}
}

func TestPingConnectionRefused(t *testing.T) {
	ln := tcpListener(t)
	addr := ln.Addr().String()
	_ = ln.Close()
	if err := NewClient("tcp", addr).Ping(context.Background()); err == nil {
		t.Fatal("Ping succeeded against a closed port")
	}
}

func TestPingUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "tt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	fakeClamd(t, ln, reply(t, "PONG\x00"))
	if err := NewClient("unix", path).Ping(context.Background()); err != nil {
		t.Fatalf("Ping = %v", err)
	}
}

// fakeConn is a net.Conn whose deadline, write and close can fail.
type fakeConn struct {
	net.Conn
	deadlineErr, writeErr, closeErr error
	replyData                       string
}

func (c *fakeConn) SetDeadline(time.Time) error { return c.deadlineErr }
func (c *fakeConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *fakeConn) Read(p []byte) (int, error) {
	if c.replyData == "" {
		return 0, io.EOF
	}
	n := copy(p, c.replyData)
	c.replyData = c.replyData[n:]
	return n, nil
}
func (c *fakeConn) Close() error { return c.closeErr }

func TestPingConnErrors(t *testing.T) {
	errFake := errors.New("fake")
	tests := []struct {
		name string
		conn *fakeConn
	}{
		{"set deadline", &fakeConn{deadlineErr: errFake}},
		{"write", &fakeConn{writeErr: errFake}},
		{"close", &fakeConn{closeErr: errFake, replyData: "PONG\x00"}},
		{"close after failure keeps first error", &fakeConn{closeErr: errors.New("other"), writeErr: errFake}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dial := func(context.Context, string, string) (net.Conn, error) { return tt.conn, nil }
			err := NewClient("tcp", "x", WithDialer(dial)).Ping(context.Background())
			if !errors.Is(err, errFake) {
				t.Fatalf("Ping = %v, want %v", err, errFake)
			}
		})
	}
}

// TestPingLive runs against a real clamd when TT_TEST_CLAMAV_ADDR is set
// (for example "127.0.0.1:3310").
func TestPingLive(t *testing.T) {
	addr := os.Getenv("TT_TEST_CLAMAV_ADDR")
	if addr == "" {
		t.Skip("TT_TEST_CLAMAV_ADDR not set")
	}
	if err := NewClient("tcp", addr, WithTimeout(5*time.Second)).Ping(context.Background()); err != nil {
		t.Fatalf("Ping = %v", err)
	}
}

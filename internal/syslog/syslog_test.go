package syslog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
)

// secretActor is a value that must never appear in the local warnings.
const secretActor = "actor-secret@example.com"

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func auditEvent(action string) events.Event {
	return events.Event{Type: events.LogAudit, OccurredAt: testTime, Log: &events.LogRecord{
		Stream: events.StreamAudit, Time: testTime, Tenant: "ten_01", Action: action,
		ActorKind: "sender", Actor: secretActor, IP: netip.MustParseAddr("203.0.113.7"),
	}}
}

func securityEvent(action string) events.Event {
	return events.Event{Type: events.LogSecurity, OccurredAt: testTime, Log: &events.LogRecord{
		Stream: events.StreamSecurity, Time: testTime, Tenant: "transfer.entity-a.example.com", Action: action,
		Line: "2026-10-27T08:09:10.123Z ip=- tenant=- event=" + action,
	}}
}

func mustNew(t *testing.T, opts Options) *Exporter {
	t.Helper()
	if opts.Streams == nil {
		opts.Streams = []string{"audit", "security"}
	}
	e, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// testServer is an in-process syslog server over TCP or TLS reading
// octet-counted frames.
type testServer struct {
	ln   net.Listener
	msgs chan string
}

func startStreamServer(t *testing.T, cfg *tls.Config) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
	}
	s := &testServer{ln: ln, msgs: make(chan string, 64)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *testServer) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		l, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSuffix(l, " "))
		if err != nil {
			s.msgs <- "BAD FRAME " + l
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		s.msgs <- string(buf)
	}
}

func (s *testServer) addr() string { return s.ln.Addr().String() }

func (s *testServer) next(t *testing.T) string {
	t.Helper()
	select {
	case m := <-s.msgs:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message received")
		return ""
	}
}

// testCA is a certificate authority generated for the tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// serverConfig returns a TLS server configuration with a certificate for
// 127.0.0.1 signed by ca.
func (ca *testCA) serverConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "syslog.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func (ca *testCA) file(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewValidation(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Options{
		"empty addr":      {Streams: []string{"audit"}},
		"bad protocol":    {Addr: "h:1", Protocol: "http", Streams: []string{"audit"}},
		"empty host":      {Addr: ":514", Streams: []string{"audit"}},
		"empty port":      {Addr: "h:", Streams: []string{"audit"}},
		"space in host":   {Addr: "a b", Streams: []string{"audit"}},
		"no stream":       {Addr: "h:1"},
		"bad stream":      {Addr: "h:1", Streams: []string{"audit", "mail"}},
		"negative fac":    {Addr: "h:1", Streams: []string{"audit"}, Facility: -1},
		"too big fac":     {Addr: "h:1", Streams: []string{"audit"}, Facility: 24},
		"missing CA file": {Addr: "h:1", Streams: []string{"audit"}, CAFile: filepath.Join(dir, "none.pem")},
		"CA file not PEM": {Addr: "h:1", Streams: []string{"audit"}, CAFile: notPEM},
	}
	for name, opts := range cases {
		if _, err := New(opts); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("%s: err = %v, want ErrInvalidOptions", name, err)
		}
	}
}

func TestNewDefaults(t *testing.T) {
	cases := []struct {
		addr, protocol, want, network string
	}{
		{"syslog.example.com", "", "syslog.example.com:6514", "tcp"},
		{"syslog.example.com", "tcp", "syslog.example.com:514", "tcp"},
		{"syslog.example.com:1514", "udp", "syslog.example.com:1514", "udp"},
		{"[::1]", "udp", "[::1]:514", "udp"},
		{"::1", "tls", "[::1]:6514", "tcp"},
	}
	for _, c := range cases {
		e := mustNew(t, Options{Addr: c.addr, Protocol: c.protocol})
		if e.addr != c.want || e.network != c.network {
			t.Errorf("%s/%s: addr %q network %q", c.addr, c.protocol, e.addr, e.network)
		}
	}
	e := mustNew(t, Options{Addr: "h", Protocol: "tls", Hostname: "web\x00.example.com"})
	if e.tlsConfig.ServerName != "h" || e.tlsConfig.MinVersion != tls.VersionTLS12 || e.tlsConfig.RootCAs != nil ||
		e.tlsConfig.InsecureSkipVerify {
		t.Errorf("tls config %+v", e.tlsConfig)
	}
	if e.format.hostname != "web.example.com" || e.format.procID != strconv.Itoa(os.Getpid()) || e.format.facility != 0 {
		t.Errorf("formatter %+v", e.format)
	}
	if e.timeout != DefaultTimeout || e.minBackoff != DefaultMinBackoff || e.maxBackoff != DefaultMaxBackoff ||
		e.warnInterval != DefaultWarnInterval || e.now == nil || e.dial == nil || e.logger == nil {
		t.Errorf("defaults not set")
	}
	e = mustNew(t, Options{Addr: "h", MinBackoff: 2 * time.Minute})
	if e.maxBackoff != 2*time.Minute {
		t.Errorf("max backoff %v", e.maxBackoff)
	}
}

func TestNewHostname(t *testing.T) {
	orig := osHostname
	t.Cleanup(func() { osHostname = orig })
	osHostname = func() (string, error) { return "", errors.New("no host name") }
	if e := mustNew(t, Options{Addr: "h"}); e.format.hostname != "-" {
		t.Errorf("hostname %q", e.format.hostname)
	}
	osHostname = func() (string, error) { return "node-1.example.com", nil }
	if e := mustNew(t, Options{Addr: "h"}); e.format.hostname != "node-1.example.com" {
		t.Errorf("hostname %q", e.format.hostname)
	}
}

func TestSanitizeHostname(t *testing.T) {
	if got := sanitizeHostname("é h\x7f"); got != "h" {
		t.Errorf("got %q", got)
	}
	if got := sanitizeHostname(strings.Repeat("a", 300)); got != strings.Repeat("a", MaxHostnameLen) {
		t.Errorf("not truncated: %d", len(got))
	}
	if got := sanitizeHostname(" "); got != "-" {
		t.Errorf("got %q", got)
	}
}

func TestAccepts(t *testing.T) {
	e := mustNew(t, Options{Addr: "h", Streams: []string{"security"}})
	if e.accepts(events.LogAudit) || !e.accepts(events.LogSecurity) || e.accepts(events.VirusDetected) {
		t.Error("security-only filter wrong")
	}
	e = mustNew(t, Options{Addr: "h", Streams: []string{"audit"}})
	if !e.accepts(events.LogAudit) || e.accepts(events.LogSecurity) {
		t.Error("audit-only filter wrong")
	}
}

func TestUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	e := mustNew(t, Options{Addr: pc.LocalAddr().String(), Protocol: "udp", Facility: 16, Hostname: "h.example.com"})
	ev := auditEvent("admin.login")
	ev.Log.Actor = strings.Repeat("é", 2000) // forces the datagram cut
	e.handle(context.Background(), ev)
	buf := make([]byte, 65536)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := buf[:n]
	if n > MaxDatagram || !strings.HasPrefix(string(got), "<133>1 2026-10-27T08:09:10.123456Z h.example.com transteira ") {
		t.Fatalf("datagram (%d bytes) %q", n, got)
	}
	if e.Sent() != 1 || e.Dropped() != 0 || e.Failed() != 0 {
		t.Fatalf("counters %d %d %d", e.Sent(), e.Dropped(), e.Failed())
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTCP(t *testing.T) {
	s := startStreamServer(t, nil)
	e := mustNew(t, Options{Addr: s.addr(), Protocol: "tcp", Facility: 16, Hostname: "h"})
	e.handle(context.Background(), auditEvent("admin.login"))
	ev := securityEvent("unknown_fqdn")
	ev.Log.Line += "\nforged line"
	e.handle(context.Background(), ev)
	if m := s.next(t); !strings.HasPrefix(m, "<133>1 ") || !strings.Contains(m, `actor="`+secretActor+`"`) {
		t.Fatalf("audit message %q", m)
	}
	if m := s.next(t); !strings.HasPrefix(m, "<132>1 ") || !strings.HasSuffix(m, `event=unknown_fqdn\nforged line`) {
		t.Fatalf("security message %q", m)
	}
	if e.Sent() != 2 {
		t.Fatalf("sent %d", e.Sent())
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.handle(context.Background(), auditEvent("after.close"))
	if e.Dropped() != 1 {
		t.Fatalf("message after Close not dropped")
	}
}

func TestTLS(t *testing.T) {
	ca := newTestCA(t)
	s := startStreamServer(t, ca.serverConfig(t))
	e := mustNew(t, Options{Addr: s.addr(), Protocol: "tls", CAFile: ca.file(t)})
	e.handle(context.Background(), securityEvent("admin_login_failed"))
	if m := s.next(t); !strings.Contains(m, "admin_login_failed") {
		t.Fatalf("message %q", m)
	}
	if e.Sent() != 1 || e.Failed() != 0 {
		t.Fatalf("counters sent %d failed %d", e.Sent(), e.Failed())
	}
	if _, ok := e.conn.(*tls.Conn); !ok {
		t.Fatalf("connection is %T", e.conn)
	}
	_ = e.Close(context.Background())
}

func TestTLSRefusesUntrustedCertificate(t *testing.T) {
	ca := newTestCA(t)
	s := startStreamServer(t, ca.serverConfig(t))
	for name, caFile := range map[string]string{"system roots": "", "wrong CA": newTestCA(t).file(t)} {
		logs := &syncBuffer{}
		e := mustNew(t, Options{Addr: s.addr(), Protocol: "tls", CAFile: caFile, Logger: slog.New(slog.NewTextHandler(logs, nil))})
		e.handle(context.Background(), auditEvent("admin.login"))
		if e.Sent() != 0 || e.Dropped() != 1 || e.Failed() != 1 || e.conn != nil {
			t.Errorf("%s: sent %d dropped %d failed %d", name, e.Sent(), e.Dropped(), e.Failed())
		}
		if out := logs.String(); !strings.Contains(out, "certificate") || strings.Contains(out, secretActor) {
			t.Errorf("%s: warning %q", name, out)
		}
	}
	select {
	case m := <-s.msgs:
		t.Fatalf("message delivered despite the untrusted certificate: %q", m)
	default:
	}
}

func TestServerDownBackoffAndReconnect(t *testing.T) {
	s := startStreamServer(t, nil)
	clock := &fakeClock{t: testTime}
	var down atomic.Bool
	down.Store(true)
	var dials atomic.Int32
	logs := &syncBuffer{}
	e := mustNew(t, Options{
		Addr: s.addr(), Protocol: "tcp", Now: clock.Now, Logger: slog.New(slog.NewTextHandler(logs, nil)),
		MinBackoff: time.Second, MaxBackoff: 4 * time.Second,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			if down.Load() {
				return nil, errors.New("connection refused")
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	step := func(wantDials int32, wantDropped, wantSent uint64) {
		t.Helper()
		e.handle(context.Background(), auditEvent("transfer.created"))
		if dials.Load() != wantDials || e.Dropped() != wantDropped || e.Sent() != wantSent {
			t.Fatalf("dials %d dropped %d sent %d, want %d %d %d",
				dials.Load(), e.Dropped(), e.Sent(), wantDials, wantDropped, wantSent)
		}
	}
	step(1, 1, 0) // refused: backoff 1s
	step(1, 2, 0) // in backoff: dropped without dialing
	clock.Advance(time.Second)
	step(2, 3, 0) // refused again: backoff 2s
	clock.Advance(time.Second)
	step(2, 4, 0)
	down.Store(false)
	clock.Advance(time.Second)
	step(3, 4, 1) // reconnected
	if e.failures != 0 || e.Failed() != 2 {
		t.Fatalf("failures %d failed %d", e.failures, e.Failed())
	}
	if m := s.next(t); !strings.Contains(m, "transfer.created") {
		t.Fatalf("message %q", m)
	}
	out := logs.String()
	if strings.Count(out, "messages dropped") != 1 || strings.Contains(out, secretActor) || !strings.Contains(out, "connection refused") {
		t.Fatalf("warnings %q", out)
	}
	// A new failure after the warning interval is reported again.
	_ = e.Close(context.Background())
	e.closed = false
	down.Store(true)
	clock.Advance(DefaultWarnInterval)
	e.handle(context.Background(), auditEvent("transfer.created"))
	if strings.Count(logs.String(), "messages dropped") != 2 {
		t.Fatalf("second warning missing: %q", logs.String())
	}
}

func TestBackoffGrowth(t *testing.T) {
	clock := &fakeClock{t: testTime}
	e := mustNew(t, Options{Addr: "h", Now: clock.Now, MinBackoff: time.Second, MaxBackoff: 4 * time.Second})
	for i, want := range []time.Duration{1, 2, 4, 4, 4} {
		e.fail()
		if got := e.nextAttempt.Sub(testTime); got != want*time.Second {
			t.Errorf("failure %d: backoff %v, want %v", i+1, got, want*time.Second)
		}
	}
	if e.Failed() != 5 {
		t.Errorf("failed %d", e.Failed())
	}
}

// fakeConn is a connection whose writes fail on demand.
type fakeConn struct {
	net.Conn
	fail     bool
	closeErr error
	written  bytes.Buffer
	closed   bool
}

func (c *fakeConn) Write(p []byte) (int, error) {
	if c.fail {
		return 0, errors.New("broken pipe")
	}
	return c.written.Write(p)
}

func (c *fakeConn) Close() error                     { c.closed = true; return c.closeErr }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// dialSeq returns a Dial function giving the connections of conns in order,
// then an error.
func dialSeq(conns ...*fakeConn) func(context.Context, string, string) (net.Conn, error) {
	var i int
	return func(context.Context, string, string) (net.Conn, error) {
		if i >= len(conns) {
			return nil, errors.New("connection refused")
		}
		i++
		return conns[i-1], nil
	}
}

func TestWriteFailureRetriesOnNewConnection(t *testing.T) {
	c1, c2 := &fakeConn{}, &fakeConn{}
	e := mustNew(t, Options{Addr: "h:1", Protocol: "tcp", Dial: dialSeq(c1, c2)})
	e.handle(context.Background(), auditEvent("first"))
	c1.fail = true
	e.handle(context.Background(), auditEvent("second"))
	// The stale connection replaced at once is no outage: nothing counted.
	if e.Sent() != 2 || e.Dropped() != 0 || e.Failed() != 0 || e.failures != 0 || !c1.closed || e.conn != c2 {
		t.Fatalf("sent %d dropped %d failed %d", e.Sent(), e.Dropped(), e.Failed())
	}
	if !strings.Contains(c2.written.String(), "second") || !strings.HasPrefix(c1.written.String(), strconv.Itoa(len(c1.written.String())-4)+" ") {
		t.Fatalf("c1 %q c2 %q", c1.written.String(), c2.written.String())
	}
	// The retry connection fails too: the message is dropped.
	c2.fail = true
	e.handle(context.Background(), auditEvent("third"))
	if e.Sent() != 2 || e.Dropped() != 1 || e.Failed() != 1 || e.conn != nil {
		t.Fatalf("sent %d dropped %d failed %d", e.Sent(), e.Dropped(), e.Failed())
	}
}

func TestStaleConnectionAndFailedReconnectCountOneFailure(t *testing.T) {
	c1 := &fakeConn{}
	clock := &fakeClock{t: testTime}
	e := mustNew(t, Options{
		Addr: "h:1", Protocol: "tcp", Dial: dialSeq(c1), Now: clock.Now,
		MinBackoff: time.Second, MaxBackoff: time.Minute,
	})
	e.handle(context.Background(), auditEvent("first"))
	c1.fail = true // the write fails, then the reconnection is refused
	e.handle(context.Background(), auditEvent("second"))
	if e.Dropped() != 1 || e.Failed() != 1 || e.failures != 1 || e.conn != nil {
		t.Fatalf("dropped %d failed %d failures %d", e.Dropped(), e.Failed(), e.failures)
	}
	if got := e.nextAttempt.Sub(testTime); got != time.Second {
		t.Fatalf("backoff %v, want 1s", got)
	}
	// In backoff: dropped without any attempt and without a new failure.
	e.handle(context.Background(), auditEvent("third"))
	if e.Dropped() != 2 || e.Failed() != 1 {
		t.Fatalf("dropped %d failed %d", e.Dropped(), e.Failed())
	}
	// The next outage doubles the delay.
	clock.Advance(time.Second)
	e.handle(context.Background(), auditEvent("fourth"))
	if e.Failed() != 2 || e.nextAttempt.Sub(clock.Now()) != 2*time.Second {
		t.Fatalf("failed %d backoff %v", e.Failed(), e.nextAttempt.Sub(clock.Now()))
	}
}

func TestWriteFailureOnFreshConnection(t *testing.T) {
	c1 := &fakeConn{fail: true}
	clock := &fakeClock{t: testTime}
	e := mustNew(t, Options{Addr: "h:1", Protocol: "tcp", Dial: dialSeq(c1), Now: clock.Now})
	e.handle(context.Background(), auditEvent("first"))
	if e.Dropped() != 1 || e.Failed() != 1 || !c1.closed || !e.nextAttempt.After(testTime) {
		t.Fatalf("dropped %d failed %d", e.Dropped(), e.Failed())
	}
}

func TestWriteCanceledByContext(t *testing.T) {
	client, server := net.Pipe() // nobody reads: the write blocks
	t.Cleanup(func() { _ = server.Close() })
	e := mustNew(t, Options{Addr: "h:1", Protocol: "tcp", Dial: func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	e.handle(ctx, auditEvent("blocked"))
	if time.Since(start) > 3*time.Second || e.Dropped() != 1 || e.Failed() != 1 {
		t.Fatalf("dropped %d failed %d after %v", e.Dropped(), e.Failed(), time.Since(start))
	}
	// A canceled context drops without any attempt.
	e.handle(ctx, auditEvent("canceled"))
	if e.Dropped() != 2 || e.Failed() != 1 {
		t.Fatalf("dropped %d failed %d", e.Dropped(), e.Failed())
	}
}

func TestHandleIgnoresOtherRecords(t *testing.T) {
	e := mustNew(t, Options{Addr: "h:1", Protocol: "tcp", Streams: []string{"audit"}, Dial: dialSeq()})
	e.handle(context.Background(), events.Event{Type: events.LogAudit})
	e.handle(context.Background(), securityEvent("unknown_fqdn"))
	if e.Sent()+e.Dropped()+e.Failed() != 0 {
		t.Fatal("ignored records were processed")
	}
}

func TestClose(t *testing.T) {
	c := &fakeConn{closeErr: errors.New("close failed")}
	e := mustNew(t, Options{Addr: "h:1", Protocol: "tcp", Dial: dialSeq(c)})
	e.handle(context.Background(), auditEvent("x"))
	if err := e.Close(context.Background()); err == nil || !c.closed || e.conn != nil {
		t.Fatalf("Close = %v", err)
	}
	// Close gives up when its context is done while a message is being sent.
	e.sem <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close = %v", err)
	}
	<-e.sem
}

func TestRegister(t *testing.T) {
	e := mustNew(t, Options{Addr: "h:1"})
	if err := e.Register(nil); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("Register(nil) = %v", err)
	}
	bus := events.New(events.Options{})
	if err := bus.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Register(bus); !errors.Is(err, events.ErrStarted) {
		t.Fatalf("Register after Start = %v", err)
	}
	_ = bus.Close(context.Background())
}

func TestBusIntegrationStreamFilter(t *testing.T) {
	s := startStreamServer(t, nil)
	e := mustNew(t, Options{Addr: s.addr(), Protocol: "tcp", Streams: []string{"security"}})
	bus := events.New(events.Options{})
	if err := e.Register(bus); err != nil {
		t.Fatal(err)
	}
	if err := bus.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus.Publish(auditEvent("admin.login"))
	bus.Publish(events.Event{Type: events.VirusDetected})
	bus.Publish(securityEvent("unknown_fqdn"))
	if err := bus.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := s.next(t); !strings.Contains(m, "unknown_fqdn") {
		t.Fatalf("message %q", m)
	}
	if e.Sent() != 1 {
		t.Fatalf("sent %d", e.Sent())
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBusNeverBlocksOnUnreachableServer(t *testing.T) {
	e := mustNew(t, Options{
		Addr: "h:1", Protocol: "tcp", Buffer: 2, Timeout: 100 * time.Millisecond,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done() // a server that never answers
			return nil, ctx.Err()
		},
	})
	bus := events.New(events.Options{})
	if err := e.Register(bus); err != nil {
		t.Fatal(err)
	}
	if err := bus.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 100 {
		bus.Publish(auditEvent("transfer.created"))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Publish blocked for %v", d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bus.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if bus.Dropped(SubscriberName) == 0 || e.Dropped() == 0 || e.Sent() != 0 {
		t.Fatalf("bus dropped %d exporter dropped %d", bus.Dropped(SubscriberName), e.Dropped())
	}
}

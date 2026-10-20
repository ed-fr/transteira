package integration_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// inFlight opens a connection and sends the head of a JSON POST with
// "Expect: 100-continue", then waits for the 100 Continue interim response,
// which proves that the handler is running and reading the body: the
// connection is active, not idle, for http.Server.Shutdown.
func inFlight(t *testing.T, s *server, body string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: waitTimeout}).DialContext(context.Background(), "tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(waitTimeout))
	head := "POST " + exampleStubPOST + " HTTP/1.1\r\nHost: " + hostA +
		"\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatalf("write head: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 100") {
		t.Fatalf("want 100 Continue, got %q (%v)", status, err)
	}
	if blank, err := br.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("malformed interim response: %q (%v)", blank, err)
	}
	return conn, br
}

// expectFileReleased checks that the server no longer holds path open. On
// Windows, renaming a file still open without FILE_SHARE_DELETE fails, so
// this detects a leaked handle; elsewhere it only checks the file exists.
func expectFileReleased(t *testing.T, path string) {
	t.Helper()
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Errorf("%s still held open after shutdown: %v", filepath.Base(path), err)
		return
	}
	if err := os.Rename(moved, path); err != nil {
		t.Errorf("restore %s: %v", filepath.Base(path), err)
	}
}

// TestGracefulShutdown cancels the server while a request is in flight: the
// request completes, new connections are refused, app.Run returns nil, and
// the security log is closed after its last line was written.
func TestGracefulShutdown(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		// One security event before shutdown, so that the file has content.
		expectProblem(t, s.get(t, "before-shutdown.example.net", "/api/v1/version"), http.StatusMisdirectedRequest, "unknown-tenant")

		body := `{}`
		conn, br := inFlight(t, s, body)
		s.cancel()
		select {
		case <-s.appLog.wait(`"msg":"shutting down"`):
		case <-time.After(waitTimeout):
			t.Fatal("no shutdown log line")
		}
		if _, err := io.WriteString(conn, body); err != nil {
			t.Fatalf("finish the in-flight body: %v", err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("in-flight request aborted by shutdown: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound { // the stub
			t.Errorf("in-flight request: status %d, want 404", resp.StatusCode)
		}

		if err := s.stop(); err != nil {
			t.Fatalf("app.Run = %v, want nil after a graceful shutdown", err)
		}
		if c, err := net.DialTimeout("tcp", s.addr, 2*time.Second); err == nil {
			_ = c.Close()
			t.Error("the listener still accepts connections after app.Run returned")
		}
		if !strings.Contains(s.appLog.String(), `"msg":"stopped"`) {
			t.Errorf("no \"stopped\" log line:\n%s", s.appLog)
		}
		expectFileReleased(t, filepath.Join(s.logDir, app.SecurityLogName))
		if e.Driver == "sqlite" {
			expectFileReleased(t, e.DSN)
		}
		if n := len(eventsOf(t, s.securityLines(t), "unknown_fqdn")); n != 1 {
			t.Errorf("security log lost lines: %d unknown_fqdn, want 1", n)
		}
	})
}

// TestShutdownTimeout checks the forced path: a request that never
// completes outlives the shutdown timeout; app.Run logs a warning, closes
// the active connections, returns nil and still releases the security log
// and the database.
func TestShutdownTimeout(t *testing.T) {
	t.Parallel()
	e := storetest.SQLite(t)
	s := startServer(t, e, serverOptions{shutdownTimeout: 500 * time.Millisecond})
	inFlight(t, s, `{"never":"sent"}`)
	if err := s.stop(); err != nil {
		t.Fatalf("app.Run = %v, want nil after a forced close", err)
	}
	if !strings.Contains(s.appLog.String(), "graceful shutdown timed out: forcing close of active connections") {
		t.Errorf("no forced-close warning:\n%s", s.appLog)
	}
	expectFileReleased(t, filepath.Join(s.logDir, app.SecurityLogName))
	expectFileReleased(t, e.DSN)
}

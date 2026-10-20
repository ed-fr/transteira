package httpserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

// fakeUploads answers the tus operations: Append drains the body.
type fakeUploads struct {
	err     error
	mu      sync.Mutex
	got     []byte
	readErr error
}

func (f *fakeUploads) Status(context.Context, tenant.ID, upload.Principal, string) (upload.Status, error) {
	return upload.Status{Offset: 3, Length: 10, ExpiresAt: time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)}, f.err
}

func (f *fakeUploads) Append(_ context.Context, _ tenant.ID, _ upload.Principal, _ string, offset int64, body io.Reader) (upload.Status, error) {
	b, err := io.ReadAll(body)
	f.mu.Lock()
	f.got, f.readErr = b, err
	f.mu.Unlock()
	if err != nil {
		return upload.Status{Offset: offset + int64(len(b))}, upload.ErrInterrupted
	}
	if f.err != nil {
		return upload.Status{}, f.err
	}
	return upload.Status{Offset: offset + int64(len(b)), Length: 10, ExpiresAt: time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)}, nil
}

func (f *fakeUploads) Terminate(context.Context, tenant.ID, upload.Principal, string) error {
	return f.err
}

func newTusEnv(t *testing.T, up *fakeUploads, idle time.Duration) *env {
	t.Helper()
	return newEnv(t, envConfig{
		api: public.NewServer(public.WithUploads(up)), sessions: fakeSessions{}, idle: idle,
	})
}

func TestTusProtocol(t *testing.T) {
	t.Parallel()
	cookie := middleware.DepositCookie + "=" + goodToken
	const target = "/api/v1/uploads/upl_x"
	octets := "application/offset+octet-stream"
	tests := []struct {
		name   string
		method string
		body   string
		hdr    []string
		err    error
		status int
		check  func(t *testing.T, rec *httptest.ResponseRecorder)
	}{
		{
			name: "capabilities", method: http.MethodOptions, status: http.StatusNoContent,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()
				h := rec.Header()
				if h.Get("Tus-Version") != "1.0.0" || h.Get("Tus-Extension") != "expiration,termination" || h.Get("Tus-Max-Size") != "0" {
					t.Errorf("capabilities headers %v", h)
				}
			},
		},
		{
			name: "head wrong version", method: http.MethodHead, hdr: []string{"Tus-Resumable", "0.2.2", "Cookie", cookie},
			status: http.StatusPreconditionFailed,
		},
		{name: "head unauthenticated", method: http.MethodHead, hdr: []string{"Tus-Resumable", "1.0.0"}, status: http.StatusUnauthorized},
		{
			name: "head", method: http.MethodHead, hdr: []string{"Tus-Resumable", "1.0.0", "Cookie", cookie}, status: http.StatusOK,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()
				h := rec.Header()
				if h.Get("Upload-Offset") != "3" || h.Get("Upload-Length") != "10" ||
					h.Get("Upload-Expires") != "Wed, 21 Oct 2026 16:00:00 GMT" || h.Get("Cache-Control") != "no-store" {
					t.Errorf("HEAD headers %v", h)
				}
			},
		},
		{
			name: "head not found", method: http.MethodHead, hdr: []string{"Tus-Resumable", "1.0.0", "Cookie", cookie},
			err: upload.ErrNotFound, status: http.StatusNotFound,
		},
		{
			name: "patch wrong media type", method: http.MethodPatch, body: "abc",
			hdr:    []string{"Tus-Resumable", "1.0.0", "Upload-Offset", "3", "Content-Type", "application/octet-stream", "Cookie", cookie, "X-CSRF-Token", goodCSRF},
			status: http.StatusUnsupportedMediaType,
		},
		{
			name: "patch without csrf", method: http.MethodPatch, body: "abc",
			hdr:    []string{"Tus-Resumable", "1.0.0", "Upload-Offset", "3", "Content-Type", octets, "Cookie", cookie},
			status: http.StatusForbidden,
		},
		{
			name: "patch", method: http.MethodPatch, body: "abc",
			hdr:    []string{"Tus-Resumable", "1.0.0", "Upload-Offset", "3", "Content-Type", octets + "; charset=binary", "Cookie", cookie, "X-CSRF-Token", goodCSRF},
			status: http.StatusNoContent,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()
				if rec.Header().Get("Upload-Offset") != "6" || rec.Header().Get("Upload-Expires") == "" {
					t.Errorf("PATCH headers %v", rec.Header())
				}
			},
		},
		{
			name: "patch offset mismatch", method: http.MethodPatch, body: "abc",
			hdr: []string{"Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", octets, "Cookie", cookie, "X-CSRF-Token", goodCSRF},
			err: upload.ErrOffsetMismatch, status: http.StatusConflict,
		},
		{
			name: "delete", method: http.MethodDelete, hdr: []string{"Tus-Resumable", "1.0.0", "Cookie", cookie, "X-CSRF-Token", goodCSRF},
			status: http.StatusNoContent,
		},
		{
			name: "delete finalized", method: http.MethodDelete, hdr: []string{"Tus-Resumable", "1.0.0", "Cookie", cookie, "X-CSRF-Token", goodCSRF},
			err: upload.ErrFinalized, status: http.StatusConflict,
		},
		{
			name: "server error keeps its problem", method: http.MethodDelete,
			hdr: []string{"Tus-Resumable", "1.0.0", "Cookie", cookie, "X-CSRF-Token", goodCSRF},
			err: errors.New("disk on fire"), status: http.StatusInternalServerError,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()
				decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTusEnv(t, &fakeUploads{err: tt.err}, 0)
			path := target
			if tt.method == http.MethodOptions {
				path = "/api/v1/uploads"
			}
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			rec := e.do(t, tt.method, path, hostA, body, tt.hdr...)
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tt.status, rec.Body)
			}
			if rec.Header().Get("Tus-Resumable") != "1.0.0" {
				t.Errorf("Tus-Resumable = %q", rec.Header().Get("Tus-Resumable"))
			}
			if tt.status >= 400 && tt.status != http.StatusInternalServerError {
				if rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
					t.Errorf("tus error with a body: %q, Content-Type %q", rec.Body, rec.Header().Get("Content-Type"))
				}
			}
			if tt.status >= 400 && rec.Header().Get("Connection") != "close" {
				t.Errorf("tus error without Connection: close: %v", rec.Header())
			}
			if tt.status == http.StatusPreconditionFailed && rec.Header().Get("Tus-Version") != "1.0.0" {
				t.Errorf("412 without Tus-Version: %v", rec.Header())
			}
			if tt.check != nil {
				tt.check(t, rec)
			}
		})
	}
}

func TestTusWriter(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	w := &tusWriter{ResponseWriter: rec}
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	w.WriteHeader(http.StatusTeapot) // superfluous: ignored
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" || rec.Header().Get("Tus-Resumable") != "1.0.0" {
		t.Errorf("implicit 200: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	if w.Unwrap() != rec {
		t.Error("Unwrap does not return the wrapped writer")
	}
}

// TestTusIdleTimeout sends the head and part of a PATCH body on a real
// connection, then stalls: the body read fails after the idle timeout, the
// handler answers 400 and the bytes received reached the upload engine.
func TestTusIdleTimeout(t *testing.T) {
	t.Parallel()
	up := &fakeUploads{}
	e := newTusEnv(t, up, 100*time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = hostA
		e.handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	head := "PATCH /api/v1/uploads/upl_x HTTP/1.1\r\nHost: " + hostA + "\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: 0\r\n" +
		"Content-Type: application/offset+octet-stream\r\nContent-Length: 10\r\nCookie: " + middleware.DepositCookie + "=" + goodToken +
		"\r\nX-CSRF-Token: " + goodCSRF + "\r\n\r\nabc"
	start := time.Now()
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Tus-Resumable") != "1.0.0" {
		t.Errorf("stalled PATCH: %d %v", resp.StatusCode, resp.Header)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 5*time.Second {
		t.Errorf("answered after %s, want about the idle timeout", d)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if string(up.got) != "abc" || up.readErr == nil {
		t.Errorf("engine got %q (error %v), want the 3 bytes then a read error", up.got, up.readErr)
	}
}

// TestTusTricklingUnauthenticatedPatch sends a refused tus request (mostly
// PATCH) with a chunked body that trickles a byte every 20 ms on a real
// connection: the 401 comes at once with Connection: close, and the server
// closes the connection within about the idle timeout instead of draining
// the trickle forever (security finding L1).
func TestTusTricklingUnauthenticatedPatch(t *testing.T) {
	t.Parallel()
	const idle = 200 * time.Millisecond
	for _, tc := range []struct {
		name   string
		method string
		header string
		status int
	}{
		{"unauthenticated", http.MethodPatch, "Tus-Resumable: 1.0.0\r\nUpload-Offset: 0\r\n", http.StatusUnauthorized},
		{"parameter error", http.MethodPatch, "Tus-Resumable: 1.0.0\r\n", http.StatusBadRequest},
		{"protocol version", http.MethodPatch, "Tus-Resumable: 0.2.2\r\nUpload-Offset: 0\r\n", http.StatusPreconditionFailed},
		// HEAD has no idle body, but its read deadline is set before the
		// parameter binding fails (security finding LOW-2).
		{"HEAD without Tus-Resumable", http.MethodHead, "", http.StatusPreconditionFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newTusEnv(t, &fakeUploads{}, idle)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Host = hostA
				e.handler.ServeHTTP(w, r)
			}))
			defer srv.Close()
			conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			head := tc.method + " /api/v1/uploads/upl_x HTTP/1.1\r\nHost: " + hostA + "\r\n" + tc.header +
				"Content-Type: application/offset+octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n"
			if _, err := io.WriteString(conn, head); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			defer close(done)
			go func() { // the trickle
				for {
					select {
					case <-done:
						return
					case <-time.After(20 * time.Millisecond):
						if _, err := io.WriteString(conn, "1\r\nx\r\n"); err != nil {
							return
						}
					}
				}
			}()
			br := bufio.NewReader(conn)
			var req *http.Request
			if tc.method == http.MethodHead {
				req = &http.Request{Method: http.MethodHead}
			}
			resp, err := http.ReadResponse(br, req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status || !resp.Close {
				t.Errorf("status %d, Connection close %v; want %d with Connection: close", resp.StatusCode, resp.Close, tc.status)
			}
			start := time.Now()
			if _, err := br.ReadByte(); err == nil {
				t.Fatal("data after the response")
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("the server kept the trickling connection open")
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("connection closed after %s, want about %s", d, idle)
			}
		})
	}
}

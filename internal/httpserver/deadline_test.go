package httpserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
)

// dialEnv serves e.handler on a real connection, keeping the Host of each
// request, and returns a raw client connection with a 10 s safety deadline.
func dialEnv(t *testing.T, e *env) net.Conn {
	t.Helper()
	srv := httptest.NewServer(e.handler)
	t.Cleanup(srv.Close)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

// TestDefaultDeadlineBeforeRouting sends requests refused before any
// operation is chosen, with a chunked body that trickles a byte every 20 ms
// on a real connection: net/http drains the unread body after the handler,
// and the default deadline makes the server close the connection after
// about that deadline instead of draining the trickle for minutes (threat
// T-123).
func TestDefaultDeadlineBeforeRouting(t *testing.T) {
	t.Parallel()
	const deadline = 200 * time.Millisecond
	for _, tc := range []struct {
		name   string
		method string
		target string
		host   string
		deny   bool
		status string
	}{
		{"unknown host", http.MethodPost, "/x", hostUnknown, false, "421"},
		{"rate limited", http.MethodPost, "/x", hostA, true, "429"},
		{"tenant admin prefix", http.MethodPost, "/api/v1/admin/tenants", hostA, false, "404"},
		{"bare API prefix", http.MethodPost, "/api/v1", hostA, false, "404"},
		{"admin host unknown route", http.MethodPost, "/api/v1/admin/nothing", hostAdmin, false, "404"},
		{"admin host method", http.MethodPost, "/api/v1/version", hostAdmin, false, "405"},
		{"spec method", http.MethodPost, SpecPath, hostUnknown, false, "405"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := []Option{withDefaultDeadline(deadline)}
			if tc.deny {
				opts = append(opts, WithGlobalLimiter(denyLimiter{}))
			}
			conn := dialEnv(t, newEnv(t, envConfig{opts: opts}))
			head := tc.method + " " + tc.target + " HTTP/1.1\r\nHost: " + tc.host + "\r\n" +
				"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n"
			start := time.Now()
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
			// The response may be lost when the write deadline expires
			// with the read deadline; what matters is that the server
			// closes the connection.
			got, err := io.ReadAll(conn)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("the server kept the trickling connection open (got %q)", got)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("connection closed after %s, want about %s", d, deadline)
			}
			if len(got) > 0 && !strings.HasPrefix(string(got), "HTTP/1.1 "+tc.status+" ") {
				t.Errorf("response %q, want status %s", got, tc.status)
			}
		})
	}
}

// TestDefaultDeadlineReplacedByPolicy checks, through the whole chain,
// that the deadlines left when the operation runs are those of its policy,
// not the default deadline: the policy deadline for an ordinary operation,
// none for the streaming routes (the idle read timeout of a tus PATCH, the
// idle write timeout of a download), and the default for a request refused
// before routing.
func TestDefaultDeadlineReplacedByPolicy(t *testing.T) {
	t.Parallel()
	const (
		def  = 50 * time.Millisecond
		idle = 7 * time.Second
	)
	e := newEnv(t, envConfig{
		opts: []Option{withDefaultDeadline(def)}, idle: idle, downloadIdle: idle,
		api:      public.NewServer(public.WithUploads(&fakeUploads{}), public.WithDownloads(fakeDownloads{})),
		sessions: fakeSessions{},
	})
	tusHdr := []string{
		"Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", "application/offset+octet-stream",
		"Cookie", middleware.DepositCookie + "=" + goodToken, "X-CSRF-Token", goodCSRF,
	}
	for _, tt := range []struct {
		name                string
		method, target      string
		host                string
		hdr                 []string
		wantRead, wantWrite time.Duration // -1: none
	}{
		{"unknown host", http.MethodGet, "/x", hostUnknown, nil, def, def},
		{"ordinary operation", http.MethodGet, "/api/v1/version", hostA, nil, RequestDeadline, RequestDeadline},
		{"image operation", http.MethodGet, "/api/v1/tenant/assets/logo", hostA, nil, ImageDeadline, ImageDeadline},
		{"tus PATCH", http.MethodPatch, "/api/v1/uploads/upl_x", hostA, tusHdr, idle, -1},
		{"download", http.MethodGet, "/api/v1/downloads/dl_x/archive", hostA, nil, -1, idle},
	} {
		req := httptest.NewRequest(tt.method, tt.target, strings.NewReader("abc"))
		req.Host = tt.host
		for i := 0; i+1 < len(tt.hdr); i += 2 {
			req.Header.Set(tt.hdr[i], tt.hdr[i+1])
		}
		w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
		start := time.Now()
		e.handler.ServeHTTP(w, req)
		for _, c := range []struct {
			kind string
			got  time.Time
			want time.Duration
		}{{"read", w.read, tt.wantRead}, {"write", w.write, tt.wantWrite}} {
			if c.want < 0 {
				if !c.got.IsZero() {
					t.Errorf("%s: %s deadline %v, want none", tt.name, c.kind, c.got)
				}
				continue
			}
			if c.got.Before(start.Add(c.want)) || c.got.After(time.Now().Add(c.want)) {
				t.Errorf("%s: %s deadline %v, want now+%v (status %d)", tt.name, c.kind, c.got.Sub(start), c.want, w.Code)
			}
		}
	}
}

// slowContent is a download content whose every Read waits, so that the
// response lasts several times the default deadline.
type slowContent struct{ *bytes.Reader }

func (c *slowContent) Read(p []byte) (int, error) {
	time.Sleep(40 * time.Millisecond)
	return c.Reader.Read(p[:min(len(p), 32<<10)])
}

func (*slowContent) Delivered()                  {}
func (*slowContent) Close(context.Context) error { return nil }

// slowDownloads serves a slowContent of size bytes.
type slowDownloads struct {
	fakeDownloads
	size int
}

func (d slowDownloads) OpenFile(context.Context, *tenant.Tenant, string, netip.Addr, string, string) (public.DownloadFile, error) {
	return public.DownloadFile{Name: "big.bin", Content: &slowContent{Reader: bytes.NewReader(make([]byte, d.size))}}, nil
}

// TestDefaultDeadlineSparesStreaming checks on a real keep-alive connection
// that the default deadline never cuts a streaming route: after a request
// refused before routing (default deadline only), a download lasting
// several times the default deadline, then a tus PATCH whose body trickles
// for longer than it, both complete.
func TestDefaultDeadlineSparesStreaming(t *testing.T) {
	t.Parallel()
	const def = 100 * time.Millisecond
	const size = 256 << 10 // 8 slow reads of 32 KiB: about 320 ms
	up := &fakeUploads{}
	e := newEnv(t, envConfig{
		opts: []Option{withDefaultDeadline(def)}, idle: 2 * time.Second, downloadIdle: 2 * time.Second,
		api:      public.NewServer(public.WithUploads(up), public.WithDownloads(slowDownloads{size: size})),
		sessions: fakeSessions{},
	})
	conn := dialEnv(t, e)
	br := bufio.NewReader(conn)
	// roundTrip writes raw and reads the response and its body: status,
	// Connection: close, body length and read error.
	roundTrip := func(raw string) (int, bool, int64, error) {
		t.Helper()
		if _, err := io.WriteString(conn, raw); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		n, err := io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Close, n, err
	}

	status, closed, _, _ := roundTrip("GET /api/v1/admin HTTP/1.1\r\nHost: " + hostA + "\r\n\r\n")
	if status != http.StatusNotFound || closed {
		t.Fatalf("refused request: %d, close %v", status, closed)
	}

	start := time.Now()
	status, _, n, err := roundTrip("GET /api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/files/fil_01JABCD9F1A2B3C4D5E6F7G8H9 HTTP/1.1\r\nHost: " +
		hostA + "\r\n\r\n")
	if status != http.StatusOK || err != nil || n != size {
		t.Fatalf("download: %d, %d bytes of %d, error %v", status, n, size, err)
	}
	if d := time.Since(start); d < 2*def {
		t.Fatalf("download lasted %s, not longer than the default deadline", d)
	}

	head := "PATCH /api/v1/uploads/upl_x HTTP/1.1\r\nHost: " + hostA + "\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: 0\r\n" +
		"Content-Type: application/offset+octet-stream\r\nContent-Length: 6\r\nCookie: " + middleware.DepositCookie + "=" + goodToken +
		"\r\nX-CSRF-Token: " + goodCSRF + "\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"a", "b", "c", "d", "e"} { // 5 x 60 ms: about 300 ms
		time.Sleep(60 * time.Millisecond)
		if _, err := io.WriteString(conn, b); err != nil {
			t.Fatal(err)
		}
	}
	if status, _, _, _ = roundTrip("f"); status != http.StatusNoContent {
		t.Errorf("trickled PATCH: %d", status)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if string(up.got) != "abcdef" || up.readErr != nil {
		t.Errorf("engine got %q (error %v), want the 6 bytes", up.got, up.readErr)
	}
}

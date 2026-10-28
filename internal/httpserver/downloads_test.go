package httpserver

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/tenant"
)

// attachmentCSP is the Content-Security-Policy expected on file and
// archive responses.
const attachmentCSP = "default-src 'none'; sandbox; frame-ancestors 'none'"

// fakeDownloads serves one file "0123456789" for the grant "dg_ok".
type fakeDownloads struct{}

func (fakeDownloads) Resolve(context.Context, *tenant.Tenant, string, string) (download.View, error) {
	return download.View{}, download.ErrNotFound
}

func (fakeDownloads) Unlock(context.Context, *tenant.Tenant, string, netip.Addr, string, string) (string, error) {
	return "dg_ok", nil
}

func (fakeDownloads) OpenFile(_ context.Context, _ *tenant.Tenant, _ string, _ netip.Addr, grant, _ string) (public.DownloadFile, error) {
	if grant != "dg_ok" {
		return public.DownloadFile{}, download.ErrDownloadLocked
	}
	return public.DownloadFile{Name: "plans.pdf", Content: &content{Reader: bytes.NewReader([]byte("0123456789"))}}, nil
}

func (fakeDownloads) PrepareArchive(context.Context, *tenant.Tenant, string, netip.Addr, string) (public.DownloadArchive, error) {
	return nil, download.ErrGone
}

type content struct{ *bytes.Reader }

func (*content) Begin(bool) error            { return nil }
func (*content) Delivered()                  {}
func (*content) Close(context.Context) error { return nil }

var _ io.ReadSeeker = (*content)(nil)

// TestDownloadRoutes checks, through the whole chain, the request in the
// context (grant cookie, Range served by http.ServeContent) and the
// same-origin protection of the unlock.
func TestDownloadRoutes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{api: public.NewServer(public.WithDownloads(fakeDownloads{}))})
	const file = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/files/fil_01JABCD9F1A2B3C4D5E6F7G8H9"
	rec := e.do(t, http.MethodGet, file, hostA, nil)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeDownloadLocked)

	rec = e.do(t, http.MethodGet, file, hostA, nil, "Cookie", download.GrantCookieName+"=dg_ok", "Range", "bytes=2-4")
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "234" || rec.Header().Get("Content-Security-Policy") != attachmentCSP ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment;") {
		t.Errorf("ranged download: %d %q %v", rec.Code, rec.Body, rec.Header())
	}

	const unlock = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/unlock"
	body := `{"password":"secret"}`
	rec = e.do(t, http.MethodPost, unlock, hostA, strings.NewReader(body), "Content-Type", "application/json", "Origin", "https://evil.example.net")
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	rec = e.do(t, http.MethodPost, unlock, hostA, strings.NewReader(body), "Content-Type", "text/plain")
	decodeProblem(t, rec, http.StatusUnsupportedMediaType, problem.CodeUnsupportedMediaType)
	rec = e.do(t, http.MethodPost, unlock, hostA, strings.NewReader(body), "Content-Type", "application/json",
		"Origin", "https://"+hostA, "Sec-Fetch-Site", "same-origin")
	if rec.Code != http.StatusNoContent || !strings.HasPrefix(rec.Header().Get("Set-Cookie"), download.GrantCookieName+"=dg_ok;") {
		t.Errorf("unlock: %d %v", rec.Code, rec.Header())
	}
}

// stalledContent is a large content recording when it is closed and
// whether it was credited.
type stalledContent struct {
	*bytes.Reader
	closed    chan struct{}
	delivered atomic.Bool
}

func (*stalledContent) Begin(bool) error { return nil }
func (c *stalledContent) Delivered()     { c.delivered.Store(true) }
func (c *stalledContent) Close(context.Context) error {
	close(c.closed)
	return nil
}

// stalledDownloads serves a 64 MiB file to anyone.
type stalledDownloads struct {
	fakeDownloads
	content *stalledContent
}

func (d stalledDownloads) OpenFile(context.Context, *tenant.Tenant, string, netip.Addr, string, string) (public.DownloadFile, error) {
	return public.DownloadFile{Name: "big.bin", Content: d.content}, nil
}

// TestDownloadStalledReader: a client that stops reading a download is cut
// after about the idle write timeout, its stream released and the content
// not credited (security finding M1).
func TestDownloadStalledReader(t *testing.T) {
	t.Parallel()
	const idle = 200 * time.Millisecond
	c := &stalledContent{Reader: bytes.NewReader(make([]byte, 64<<20)), closed: make(chan struct{})}
	e := newEnv(t, envConfig{api: public.NewServer(public.WithDownloads(stalledDownloads{content: c})), downloadIdle: idle})
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
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	start := time.Now()
	if _, err := io.WriteString(conn, "GET /api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/files/fil_01JABCD9F1A2B3C4D5E6F7G8H9 HTTP/1.1\r\nHost: "+
		hostA+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	// The client never reads.
	select {
	case <-c.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the stalled download was never cut")
	}
	if d := time.Since(start); d < idle {
		t.Errorf("cut after %s, before the idle timeout %s", d, idle)
	}
	if c.delivered.Load() {
		t.Error("a cut download was credited as delivered")
	}
}

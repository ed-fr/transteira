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

// fakeDownloads serves one file "0123456789" for the grant "dg_ok", and
// verifies the recipient of a link for the code "123456" when the
// verification cookie is "rv_ok".
type fakeDownloads struct{}

func (fakeDownloads) Resolve(context.Context, *tenant.Tenant, string, download.Cookies) (download.View, error) {
	return download.View{}, download.ErrNotFound
}

func (fakeDownloads) Unlock(context.Context, *tenant.Tenant, string, netip.Addr, string, download.Cookies) (string, error) {
	return "dg_ok", nil
}

func (fakeDownloads) OpenFile(_ context.Context, _ *tenant.Tenant, _ string, _ netip.Addr, c download.Cookies, _ string) (public.DownloadFile, error) {
	if c.Verification == "rv_missing" {
		return public.DownloadFile{}, download.ErrVerificationRequired
	}
	if c.Grant != "dg_ok" {
		return public.DownloadFile{}, download.ErrDownloadLocked
	}
	return public.DownloadFile{Name: "plans.pdf", Content: &content{Reader: bytes.NewReader([]byte("0123456789"))}}, nil
}

func (fakeDownloads) PrepareArchive(context.Context, *tenant.Tenant, string, netip.Addr, download.Cookies) (public.DownloadArchive, error) {
	return nil, download.ErrGone
}

func (fakeDownloads) StartVerification(_ context.Context, _ *tenant.Tenant, _ string, _ netip.Addr, _ bool, _, cookie string) (*download.Challenge, error) {
	if cookie == "rv_ok" {
		return nil, nil
	}
	return &download.Challenge{EmailMasked: "c***@customer.example.net", AttemptsRemaining: 2}, nil
}

func (fakeDownloads) ConfirmVerification(_ context.Context, _ *tenant.Tenant, _ string, _ netip.Addr, code, _ string) (string, error) {
	if code != "123456" {
		return "", &download.WrongCodeError{Remaining: 1}
	}
	return "rv_ok", nil
}

// ReportAbuse accepts the reports of the link that answers (dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf) and
// refuses the others.
func (fakeDownloads) ReportAbuse(_ context.Context, _ *tenant.Tenant, token string, _ netip.Addr, _, category, _ string) error {
	if category == "" || category == "bad" {
		return download.ErrInvalidCategory
	}
	if token != "dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf" {
		return download.ErrNotFound
	}
	return nil
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

	// A file of a link awaiting its verification: a plain Problem.
	rec = e.do(t, http.MethodGet, file, hostA, nil, "Cookie", download.VerificationCookieName+"=rv_missing")
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeRecipientVerificationRequired)
	if rec.Header().Get("Content-Disposition") != "" {
		t.Errorf("verification required answered as an attachment: %v", rec.Header())
	}
}

// TestRecipientVerificationRoutes checks, through the whole chain, the
// same-origin and JSON protections of the two recipient verification
// operations, the cookie read from the request and the cookie set.
func TestRecipientVerificationRoutes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{api: public.NewServer(public.WithDownloads(fakeDownloads{}))})
	const (
		start   = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/verification"
		confirm = start + "/confirm"
	)
	for _, tc := range []struct{ path, body string }{
		{start, `{"purpose":"download"}`},
		{confirm, `{"code":"123456"}`},
	} {
		rec := e.do(t, http.MethodPost, tc.path, hostA, strings.NewReader(tc.body), "Content-Type", "application/json",
			"Origin", "https://evil.example.net")
		decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
		rec = e.do(t, http.MethodPost, tc.path, hostA, strings.NewReader(tc.body), "Content-Type", "application/json",
			"Sec-Fetch-Site", "cross-site")
		decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
		rec = e.do(t, http.MethodPost, tc.path, hostA, strings.NewReader(tc.body), "Content-Type", "text/plain")
		decodeProblem(t, rec, http.StatusUnsupportedMediaType, problem.CodeUnsupportedMediaType)
	}
	same := []string{"Content-Type", "application/json", "Origin", "https://" + hostA, "Sec-Fetch-Site", "same-origin"}
	rec := e.do(t, http.MethodPost, start, hostA, strings.NewReader(`{}`), same...)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"emailMasked":"c***@customer.example.net"`) {
		t.Errorf("start: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(t, http.MethodPost, start, hostA, strings.NewReader(`{}`),
		append(same, "Cookie", download.VerificationCookieName+"=rv_ok")...)
	if rec.Code != http.StatusNoContent {
		t.Errorf("start when verified: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(t, http.MethodPost, confirm, hostA, strings.NewReader(`{"code":"000000"}`), same...)
	decodeProblem(t, rec, http.StatusUnprocessableEntity, problem.CodeVerificationCodeInvalid)
	rec = e.do(t, http.MethodPost, confirm, hostA, strings.NewReader(`{"code":"123456"}`), same...)
	cookie := rec.Header().Get("Set-Cookie")
	if rec.Code != http.StatusNoContent || !strings.HasPrefix(cookie, download.VerificationCookieName+"=rv_ok;") ||
		!strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") ||
		!strings.Contains(cookie, "SameSite=Strict") || !strings.Contains(cookie, "Path=/") || !strings.Contains(cookie, "Max-Age=3600") {
		t.Errorf("confirm: %d %q", rec.Code, cookie)
	}
}

// TestAbuseReportRoute checks, through the whole chain, that the abuse report is
// protected like the unlock: same origin, JSON only.
func TestAbuseReportRoute(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{api: public.NewServer(public.WithDownloads(fakeDownloads{}))})
	const report = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/abuse-reports"
	body := `{"category":"spam","message":"unsolicited"}`
	rec := e.do(t, http.MethodPost, report, hostA, strings.NewReader(body), "Content-Type", "application/json", "Origin", "https://evil.example.net")
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	rec = e.do(t, http.MethodPost, report, hostA, strings.NewReader(body), "Content-Type", "application/json", "Sec-Fetch-Site", "cross-site")
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	rec = e.do(t, http.MethodPost, report, hostA, strings.NewReader(body), "Content-Type", "text/plain")
	decodeProblem(t, rec, http.StatusUnsupportedMediaType, problem.CodeUnsupportedMediaType)
	same := []string{"Content-Type", "application/json", "Origin", "https://" + hostA, "Sec-Fetch-Site", "same-origin"}
	rec = e.do(t, http.MethodPost, report, hostA, strings.NewReader(body), same...)
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("report: %d %q", rec.Code, rec.Body)
	}
	rec = e.do(t, http.MethodPost, report, hostA, strings.NewReader(`{"category":"bad"}`), same...)
	decodeProblem(t, rec, http.StatusBadRequest, problem.CodeValidationFailed)
	rec = e.do(t, http.MethodPost, "/api/v1/downloads/dl_unknown/abuse-reports", hostA, strings.NewReader(body), same...)
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
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

func (d stalledDownloads) OpenFile(context.Context, *tenant.Tenant, string, netip.Addr, download.Cookies, string) (public.DownloadFile, error) {
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

// ReplyAccess answers the replier of the link dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf.
func (fakeDownloads) ReplyAccess(_ context.Context, _ *tenant.Tenant, token, _ string, _ netip.Addr) (download.ReplyTarget, error) {
	if token != "dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf" {
		return download.ReplyTarget{}, download.ErrReplyNotAllowed
	}
	return download.ReplyTarget{
		TransferID: "trf_01JABCD8E3W5Q2Z7K9M4N6P0RS", LinkID: "rcl_01JABCD8E3W5Q2Z7K9M4N6P0RS",
		Email: "carol@customer.example.net", Recipient: "alice@entity-a.example.com",
		TransferExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

// TestReplyRoute checks, through the whole chain, that the reply is
// protected like the unlock (same origin, JSON only), answers 201 with the
// session cookie and is refused during maintenance.
func TestReplyRoute(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{api: public.NewServer(public.WithDownloads(fakeDownloads{}), public.WithDeposit(&fakeDeposit{}))})
	const reply = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/reply"
	rec := e.do(t, http.MethodPost, reply, hostA, strings.NewReader(`{}`), "Content-Type", "application/json", "Origin", "https://evil.example.net")
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	rec = e.do(t, http.MethodPost, reply, hostA, strings.NewReader(`{}`), "Content-Type", "application/json", "Sec-Fetch-Site", "cross-site")
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	rec = e.do(t, http.MethodPost, reply, hostA, strings.NewReader(`{}`), "Content-Type", "text/plain")
	decodeProblem(t, rec, http.StatusUnsupportedMediaType, problem.CodeUnsupportedMediaType)
	same := []string{"Content-Type", "application/json", "Origin", "https://" + hostA, "Sec-Fetch-Site", "same-origin"}
	rec = e.do(t, http.MethodPost, reply, hostA, strings.NewReader(`{}`), same...)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Header().Get("Set-Cookie"), "ds_reply") ||
		!strings.Contains(rec.Body.String(), `"kind":"reply"`) {
		t.Errorf("reply: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	rec = e.do(t, http.MethodPost, "/api/v1/downloads/dl_unknown/reply", hostA, strings.NewReader(`{}`), same...)
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeReplyNotAllowed)
	e.maintenance.Store(true)
	rec = e.do(t, http.MethodPost, reply, hostA, strings.NewReader(`{}`), same...)
	decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeMaintenance)
}

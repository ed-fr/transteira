package public

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

const linkToken = "dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf" // gitleaks:allow (fictitious download token)

// fakeContent is a DownloadContent over a byte slice.
type fakeContent struct {
	*bytes.Reader
	delivered, closed bool
	// begin is the refusal of Begin; begins records its get arguments.
	begin  error
	begins []bool
}

func (c *fakeContent) Begin(get bool) error {
	c.begins = append(c.begins, get)
	return c.begin
}
func (c *fakeContent) Delivered()                  { c.delivered = true }
func (c *fakeContent) Close(context.Context) error { c.closed = true; return nil }

// fakeArchive is a DownloadArchive writing data.
type fakeArchive struct {
	data    []byte
	written bool
	closed  bool
	err     error
	// begin is the refusal of Begin; begins records its get arguments.
	begin  error
	begins []bool
}

func (a *fakeArchive) Begin(_ context.Context, get bool) error {
	a.begins = append(a.begins, get)
	return a.begin
}

func (a *fakeArchive) Close() { a.closed = true }

func (a *fakeArchive) Size() int64 { return int64(len(a.data)) }
func (a *fakeArchive) Write(_ context.Context, w io.Writer) error {
	a.written = true
	if a.err != nil {
		return a.err
	}
	_, err := w.Write(a.data)
	return err
}

// fakeDownloads records its calls.
type fakeDownloads struct {
	err     error
	view    download.View
	cookie  string
	content *fakeContent
	name    string
	sha     string
	archive *fakeArchive
	// challenge is the answer of StartVerification.
	challenge *download.Challenge
	// target is the answer of ReplyAccess.
	target download.ReplyTarget

	gotToken, gotGrant, gotVerification, gotPassword, gotFile string
	gotLanguage, gotCode                                      string
	gotCategory, gotMessage                                   string
	gotReply                                                  bool
	gotIP                                                     netip.Addr
}

func (f *fakeDownloads) Resolve(_ context.Context, _ *tenant.Tenant, token string, c download.Cookies) (download.View, error) {
	f.gotToken, f.gotGrant, f.gotVerification = token, c.Grant, c.Verification
	return f.view, f.err
}

func (f *fakeDownloads) Unlock(_ context.Context, _ *tenant.Tenant, token string, ip netip.Addr, password string, c download.Cookies) (string, error) {
	f.gotToken, f.gotIP, f.gotPassword, f.gotGrant, f.gotVerification = token, ip, password, c.Grant, c.Verification
	return f.cookie, f.err
}

func (f *fakeDownloads) OpenFile(_ context.Context, _ *tenant.Tenant, token string, ip netip.Addr, c download.Cookies, fileID string) (DownloadFile, error) {
	f.gotToken, f.gotIP, f.gotGrant, f.gotVerification, f.gotFile = token, ip, c.Grant, c.Verification, fileID
	if f.err != nil {
		return DownloadFile{}, f.err
	}
	return DownloadFile{Name: f.name, SHA256: f.sha, Content: f.content}, nil
}

func (f *fakeDownloads) PrepareArchive(_ context.Context, _ *tenant.Tenant, token string, ip netip.Addr, c download.Cookies) (DownloadArchive, error) {
	f.gotToken, f.gotIP, f.gotGrant, f.gotVerification = token, ip, c.Grant, c.Verification
	if f.err != nil {
		return nil, f.err
	}
	return f.archive, nil
}

func (f *fakeDownloads) StartVerification(_ context.Context, _ *tenant.Tenant, token string, ip netip.Addr, reply bool, lang, cookie string) (*download.Challenge, error) {
	f.gotToken, f.gotIP, f.gotReply, f.gotLanguage, f.gotVerification = token, ip, reply, lang, cookie
	return f.challenge, f.err
}

func (f *fakeDownloads) ConfirmVerification(_ context.Context, _ *tenant.Tenant, token string, ip netip.Addr, code, cookie string) (string, error) {
	f.gotToken, f.gotIP, f.gotCode, f.gotVerification = token, ip, code, cookie
	return f.cookie, f.err
}

func (f *fakeDownloads) ReportAbuse(_ context.Context, _ *tenant.Tenant, token string, ip netip.Addr, cookie, category, message string) error {
	f.gotToken, f.gotIP, f.gotVerification, f.gotCategory, f.gotMessage = token, ip, cookie, category, message
	return f.err
}

// downloadCtx returns the context of a request r under tenant A (with the
// request, as RequestMiddleware puts it, and a client IP).
func downloadCtx(t *testing.T, r *http.Request) context.Context {
	t.Helper()
	ctx := depositCtx(t, nil)
	if r != nil {
		var got context.Context
		_, _ = RequestMiddleware(func(ctx context.Context, _ http.ResponseWriter, _ *http.Request, _ any) (any, error) {
			got = ctx
			return nil, nil
		}, "DownloadFile")(ctx, nil, r, nil)
		ctx = got
	}
	return ctx
}

func withGrant(r *http.Request) *http.Request {
	r.AddCookie(&http.Cookie{Name: download.GrantCookieName, Value: "dg_grant"})
	return r
}

func TestDownloadOperationsRequireTenantAndService(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	calls := map[string]func(*Server, context.Context) error{
		"get": func(s *Server, ctx context.Context) error {
			_, err := s.GetDownload(ctx, gen.GetDownloadRequestObject{})
			return err
		},
		"unlock": func(s *Server, ctx context.Context) error {
			_, err := s.UnlockDownload(ctx, gen.UnlockDownloadRequestObject{})
			return err
		},
		"file": func(s *Server, ctx context.Context) error {
			_, err := s.DownloadFile(ctx, gen.DownloadFileRequestObject{})
			return err
		},
		"archive": func(s *Server, ctx context.Context) error {
			_, err := s.DownloadArchive(ctx, gen.DownloadArchiveRequestObject{})
			return err
		},
		"start verification": func(s *Server, ctx context.Context) error {
			_, err := s.StartRecipientVerification(ctx, gen.StartRecipientVerificationRequestObject{})
			return err
		},
		"confirm verification": func(s *Server, ctx context.Context) error {
			_, err := s.ConfirmRecipientVerification(ctx, gen.ConfirmRecipientVerificationRequestObject{})
			return err
		},
		"report abuse": func(s *Server, ctx context.Context) error {
			_, err := s.ReportAbuse(ctx, gen.ReportAbuseRequestObject{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, call(NewServer(WithDownloads(&fakeDownloads{})), context.Background()), problem.CodeUnknownTenant)
			if err := call(NewServer(), downloadCtx(t, r)); !errors.Is(err, errNoDownloadService) {
				t.Errorf("without download service: %v", err)
			}
		})
	}
	// The streaming operations need the request.
	srv := NewServer(WithDownloads(&fakeDownloads{}))
	if _, err := srv.DownloadFile(downloadCtx(t, nil), gen.DownloadFileRequestObject{}); !errors.Is(err, errNoRequest) {
		t.Errorf("file without request: %v", err)
	}
	if _, err := srv.DownloadArchive(downloadCtx(t, nil), gen.DownloadArchiveRequestObject{}); !errors.Is(err, errNoRequest) {
		t.Errorf("archive without request: %v", err)
	}
}

func TestGetDownload(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 10, 26, 16, 20, 0, 0, time.UTC)
	unlocked := download.View{
		TransferID: "trf_secret", SenderEmail: "alice@entity-a.example.com", Message: "Hello", ExpiresAt: expires,
		PasswordProtected: true, TotalBytes: 30, ArchiveAvailable: true,
		Files: []download.FileView{
			{ID: "fil_1", Name: "plans.pdf", Size: 10, MediaType: "application/pdf", SHA256: "aa", ScanStatus: store.ScanClean},
			{ID: "fil_2", Name: "big.bin", Size: 20, SHA256: "bb", ScanStatus: store.ScanNotScannedEncrypted},
		},
	}
	f := &fakeDownloads{view: unlocked}
	r := withGrant(httptest.NewRequest(http.MethodGet, "/", nil))
	resp, err := NewServer(WithDownloads(f)).GetDownload(downloadCtx(t, r), gen.GetDownloadRequestObject{LinkToken: linkToken})
	if err != nil {
		t.Fatal(err)
	}
	got := gen.PublicTransfer(resp.(gen.GetDownload200JSONResponse))
	if f.gotToken != linkToken || f.gotGrant != "dg_grant" {
		t.Errorf("service called with %q %q", f.gotToken, f.gotGrant)
	}
	if got.Locked || got.Message == nil || *got.Message != "Hello" || got.TotalBytes == nil || *got.TotalBytes != 30 ||
		got.DeleteAfterFirstDownload == nil || got.ArchiveUrl == nil || *got.ArchiveUrl != "/api/v1/downloads/"+linkToken+"/archive" ||
		got.Files == nil || len(*got.Files) != 2 || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("unlocked view = %+v", got)
	}
	f1, f2 := (*got.Files)[0], (*got.Files)[1]
	if f1.DownloadUrl != "/api/v1/downloads/"+linkToken+"/files/fil_1" || f1.MediaType == nil || f1.ScanStatus != "clean" ||
		f2.MediaType != nil || f2.ScanStatus != "not_scanned_encrypted" {
		t.Errorf("files = %+v", *got.Files)
	}

	// No archive: no archiveUrl. Locked: only four fields.
	f.view.ArchiveAvailable = false
	resp, _ = NewServer(WithDownloads(f)).GetDownload(downloadCtx(t, nil), gen.GetDownloadRequestObject{LinkToken: linkToken})
	if got := resp.(gen.GetDownload200JSONResponse); got.ArchiveUrl != nil || f.gotGrant != "" {
		t.Errorf("without archive: %+v (grant %q)", got, f.gotGrant)
	}
	f.view = download.View{SenderEmail: "alice@entity-a.example.com", ExpiresAt: expires, PasswordProtected: true, Locked: true}
	resp, _ = NewServer(WithDownloads(f)).GetDownload(downloadCtx(t, nil), gen.GetDownloadRequestObject{LinkToken: linkToken})
	if got := gen.PublicTransfer(resp.(gen.GetDownload200JSONResponse)); !got.Locked || got.Files != nil || got.Message != nil ||
		got.TotalBytes != nil || got.ArchiveUrl != nil || got.DeleteAfterFirstDownload != nil {
		t.Errorf("locked view = %+v", got)
	}

	_, err = NewServer(WithDownloads(&fakeDownloads{err: download.ErrGone})).GetDownload(downloadCtx(t, nil), gen.GetDownloadRequestObject{})
	wantProblem(t, err, problem.CodeTransferGone)
	_, err = NewServer(WithDownloads(&fakeDownloads{err: download.ErrMaxDownloads})).GetDownload(downloadCtx(t, nil), gen.GetDownloadRequestObject{})
	wantProblem(t, err, problem.CodeMaxDownloadsReached)
}

// TestGetDownloadLimitAndLevel checks downloadsRemaining and the
// confidentiality level of the download page (since 1.1).
func TestGetDownloadLimitAndLevel(t *testing.T) {
	t.Parallel()
	left, cap3 := 2, 3
	level := &download.Confidentiality{
		Key: "confidential", Labels: map[string]string{"fr": "Restreint", "en": "Confidential"},
		Rules: &store.ConfidentialityRules{
			ExpiryDaysMask: store.ExpiryMask1Day | store.ExpiryMask7Days, MaxDownloadsCap: &cap3,
			RequirePassword: true, InternalRecipientsOnly: true,
		},
	}
	f := &fakeDownloads{view: download.View{SenderEmail: "alice@entity-a.example.com", DownloadsRemaining: &left, Confidentiality: level}}
	get := func(accept string) gen.PublicTransfer {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if accept != "" {
			r.Header.Set("Accept-Language", accept)
		}
		resp, err := NewServer(WithDownloads(f)).GetDownload(downloadCtx(t, r), gen.GetDownloadRequestObject{LinkToken: linkToken})
		if err != nil {
			t.Fatal(err)
		}
		return gen.PublicTransfer(resp.(gen.GetDownload200JSONResponse))
	}
	got := get("fr-FR,fr;q=0.9")
	if got.DownloadsRemaining == nil || *got.DownloadsRemaining != 2 {
		t.Errorf("downloadsRemaining = %v", got.DownloadsRemaining)
	}
	l := got.ConfidentialityLevel
	if l == nil || l.Key != "confidential" || l.Label != "Restreint" || l.Rules == nil {
		t.Fatalf("level = %+v", l)
	}
	if r := l.Rules; fmt.Sprint(r.AllowedExpiryDays) != "[1 7]" || r.MaxDownloads == nil || *r.MaxDownloads != 3 ||
		!r.RequirePassword || !r.InternalRecipientsOnly || r.RequireRecipientVerification || r.ForceDeleteAfterFirstDownload {
		t.Errorf("rules = %+v", r)
	}
	if got := get("de"); got.ConfidentialityLevel.Label != "Confidential" { // tenant default (en)
		t.Errorf("label in the default language = %q", got.ConfidentialityLevel.Label)
	}
	// A label missing in the request language falls back to English.
	f.view.Confidentiality = &download.Confidentiality{Key: "internal", Labels: map[string]string{"en": "Internal"}}
	if got := get("fr"); got.ConfidentialityLevel.Label != "Internal" || got.ConfidentialityLevel.Rules != nil {
		t.Errorf("fallback level = %+v", got.ConfidentialityLevel)
	}
	// Locked: neither the level nor the downloads left.
	f.view.Locked = true
	f.view.Confidentiality.Rules = &store.ConfidentialityRules{RequirePassword: true}
	if got := get(""); got.DownloadsRemaining != nil || got.ConfidentialityLevel != nil {
		t.Errorf("locked: %+v", got)
	}
	// No limit, no level: both absent.
	f.view = download.View{SenderEmail: "alice@entity-a.example.com"}
	if got := get(""); got.DownloadsRemaining != nil || got.ConfidentialityLevel != nil {
		t.Errorf("without limit nor level: %+v", got)
	}
}

func TestUnlockDownload(t *testing.T) {
	t.Parallel()
	f := &fakeDownloads{cookie: "dg_new"}
	r := withGrant(httptest.NewRequest(http.MethodPost, "/", nil))
	resp, err := NewServer(WithDownloads(f)).UnlockDownload(downloadCtx(t, r), gen.UnlockDownloadRequestObject{
		LinkToken: linkToken, Body: &gen.TransferPassword{Password: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.UnlockDownload204Response)
	want := "__Host-tt_dl=dg_new; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict"
	if got.Headers.SetCookie == nil || *got.Headers.SetCookie != want {
		t.Errorf("Set-Cookie = %v, want %q", got.Headers.SetCookie, want)
	}
	if f.gotPassword != "secret" || f.gotGrant != "dg_grant" || f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("service called with %+v", f)
	}
	// A transfer without password: no cookie.
	resp, _ = NewServer(WithDownloads(&fakeDownloads{})).UnlockDownload(downloadCtx(t, nil), gen.UnlockDownloadRequestObject{
		Body: &gen.TransferPassword{Password: "x"},
	})
	if resp.(gen.UnlockDownload204Response).Headers.SetCookie != nil {
		t.Error("cookie set without grant")
	}
	_, err = NewServer(WithDownloads(f)).UnlockDownload(downloadCtx(t, nil), gen.UnlockDownloadRequestObject{})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/password" || p.Errors[0].Code != "required" {
		t.Errorf("errors = %+v", p.Errors)
	}
	_, err = NewServer(WithDownloads(f)).UnlockDownload(downloadCtx(t, nil), gen.UnlockDownloadRequestObject{Body: &gen.TransferPassword{}})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Code != "required" {
		t.Errorf("empty password: errors = %+v", p.Errors)
	}
	_, err = NewServer(WithDownloads(&fakeDownloads{err: &download.WrongPasswordError{Remaining: 1}})).UnlockDownload(downloadCtx(t, nil),
		gen.UnlockDownloadRequestObject{Body: &gen.TransferPassword{Password: "x"}})
	wantProblem(t, err, problem.CodeTransferPasswordInvalid)
}

func TestDownloadError(t *testing.T) {
	t.Parallel()
	boom := errors.New("db down")
	tests := []struct {
		err   error
		code  problem.Code
		check func(t *testing.T, p *problem.Problem)
	}{
		{err: &download.WrongPasswordError{Remaining: 2}, code: problem.CodeTransferPasswordInvalid, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.AttemptsRemaining == nil || *p.AttemptsRemaining != 2 {
				t.Errorf("attemptsRemaining = %v", p.AttemptsRemaining)
			}
		}},
		{err: fmt.Errorf("w: %w", &download.LockedError{RetryAfter: 15 * time.Minute}), code: problem.CodeTransferLocked, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 900 {
				t.Errorf("retryAfterSeconds = %v", p.RetryAfterSeconds)
			}
		}},
		{err: download.ErrInvalid, code: problem.CodeValidationFailed, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.Errors[0].Field != "/password" || p.Errors[0].Code != "invalid-format" {
				t.Errorf("errors = %+v", p.Errors)
			}
		}},
		{err: fmt.Errorf("w: %w", download.ErrPasswordRequired), code: problem.CodeValidationFailed, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.Errors[0].Field != "/password" || p.Errors[0].Code != "required" {
				t.Errorf("errors = %+v", p.Errors)
			}
		}},
		{err: &download.TooManyStreamsError{RetryAfter: 30 * time.Second}, code: problem.CodeRateLimited, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 30 {
				t.Errorf("retryAfterSeconds = %v", p.RetryAfterSeconds)
			}
		}},
		{err: download.ErrNotFound, code: problem.CodeNotFound},
		{err: download.ErrGone, code: problem.CodeTransferGone},
		{err: download.ErrMaxDownloads, code: problem.CodeMaxDownloadsReached},
		{err: download.ErrDownloadLocked, code: problem.CodeDownloadLocked},
		{err: download.ErrNoClientIP, code: problem.CodeInternalError},
		{err: boom, code: problem.CodeInternalError},
		{err: download.ErrVerificationRequired, code: problem.CodeRecipientVerificationRequired},
		{err: download.ErrRecipientVerificationRequired, code: problem.CodeRecipientVerificationRequired},
		{err: download.ErrReplyNotAllowed, code: problem.CodeReplyNotAllowed},
		{err: download.ErrVerificationNotNeeded, code: problem.CodeStateConflict},
		{err: download.ErrNoChallenge, code: problem.CodeStateConflict},
		{err: download.ErrVerificationExhausted, code: problem.CodeVerificationExhausted},
		{err: fmt.Errorf("w: %w", &download.WrongCodeError{Remaining: 1}), code: problem.CodeVerificationCodeInvalid, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.AttemptsRemaining == nil || *p.AttemptsRemaining != 1 {
				t.Errorf("attemptsRemaining = %v", p.AttemptsRemaining)
			}
		}},
		{err: download.ErrInvalidCode, code: problem.CodeValidationFailed, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.Errors[0].Field != "/code" || p.Errors[0].Code != "invalid-format" {
				t.Errorf("errors = %+v", p.Errors)
			}
		}},
		{err: &download.RateLimitError{RetryAfter: time.Hour}, code: problem.CodeRateLimited, check: func(t *testing.T, p *problem.Problem) {
			t.Helper()
			if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 3600 {
				t.Errorf("retryAfterSeconds = %v", p.RetryAfterSeconds)
			}
		}},
		{err: fmt.Errorf("%w: no smtp", download.ErrMailUnavailable), code: problem.CodeMailUnavailable},
	}
	for _, tt := range tests {
		p := problem.From(downloadError(tt.err))
		if p.Code != tt.code {
			t.Errorf("%v: code %s, want %s", tt.err, p.Code, tt.code)
			continue
		}
		if tt.check != nil {
			tt.check(t, p)
		}
	}
	if !errors.Is(downloadError(boom), boom) {
		t.Error("unknown error not passed through")
	}
}

// serveFile runs DownloadFile for r and renders its response.
func serveFile(t *testing.T, f *fakeDownloads, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	resp, err := NewServer(WithDownloads(f)).DownloadFile(downloadCtx(t, r), gen.DownloadFileRequestObject{LinkToken: linkToken, FileId: "fil_1"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitDownloadFileResponse(rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestDownloadFile(t *testing.T) {
	t.Parallel()
	data := []byte("0123456789")
	newFake := func() *fakeDownloads {
		return &fakeDownloads{name: `plans "été".pdf`, content: &fakeContent{Reader: bytes.NewReader(data)}}
	}

	f := newFake()
	rec := serveFile(t, f, withGrant(httptest.NewRequest(http.MethodGet, "/", nil)))
	h := rec.Header()
	if rec.Code != http.StatusOK || rec.Body.String() != string(data) || h.Get("Content-Type") != "application/octet-stream" ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Security-Policy") != attachmentCSP ||
		h.Get("Cache-Control") != "no-store" || len(h.Values("Accept-Ranges")) != 1 || h.Get("Accept-Ranges") != "bytes" || h.Get("ETag") != "" ||
		h.Get("Content-Disposition") != `attachment; filename="plans __t__.pdf"; filename*=UTF-8''plans%20%22%C3%A9t%C3%A9%22.pdf` {
		t.Errorf("full file: %d %q %v", rec.Code, rec.Body, h)
	}
	if !f.content.delivered || !f.content.closed || f.gotGrant != "dg_grant" || f.gotFile != "fil_1" {
		t.Errorf("content delivered %v closed %v, grant %q file %q", f.content.delivered, f.content.closed, f.gotGrant, f.gotFile)
	}

	// A single range.
	f = newFake()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Range", "bytes=2-4")
	if rec := serveFile(t, f, r); rec.Code != http.StatusPartialContent || rec.Body.String() != "234" {
		t.Errorf("single range: %d %q", rec.Code, rec.Body)
	}
	// Several ranges: the full file, without modifying the request.
	f = newFake()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Range", "bytes=0-1,4-5")
	if rec := serveFile(t, f, r); rec.Code != http.StatusOK || rec.Body.String() != string(data) {
		t.Errorf("multiple ranges: %d %q", rec.Code, rec.Body)
	}
	if r.Header.Get("Range") != "bytes=0-1,4-5" {
		t.Error("the request was modified")
	}

	// An unsatisfiable range: a Problem with Content-Range, nothing credited.
	f = newFake()
	f.sha = "abc"
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Range", "bytes=50-60")
	rec = serveFile(t, f, r)
	if rec.Code != http.StatusRequestedRangeNotSatisfiable || rec.Header().Get("Content-Range") != "bytes */10" ||
		rec.Header().Get("Content-Disposition") != "" || rec.Header().Get("ETag") != "" || rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("Content-Type") != problem.ContentType || !strings.Contains(rec.Body.String(), `"code":"range-not-satisfiable"`) {
		t.Errorf("416: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	if f.content.delivered || !f.content.closed {
		t.Errorf("416: delivered %v closed %v", f.content.delivered, f.content.closed)
	}

	// HEAD: headers only, nothing credited.
	f = newFake()
	if rec := serveFile(t, f, httptest.NewRequest(http.MethodHead, "/", nil)); rec.Code != http.StatusOK || f.content.delivered {
		t.Errorf("HEAD: %d, delivered %v", rec.Code, f.content.delivered)
	}

	// ETag: If-Range with the ETag resumes, with another ETag serves all.
	f = newFake()
	f.sha = "abc"
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Range", "bytes=2-4")
	r.Header.Set("If-Range", `"abc"`)
	if rec := serveFile(t, f, r); rec.Code != http.StatusPartialContent || rec.Header().Get("ETag") != `"abc"` {
		t.Errorf("If-Range matching: %d %v", rec.Code, rec.Header())
	}
	f = newFake()
	f.sha = "abc"
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Range", "bytes=2-4")
	r.Header.Set("If-Range", `"other"`)
	if rec := serveFile(t, f, r); rec.Code != http.StatusOK || rec.Body.String() != string(data) {
		t.Errorf("If-Range not matching: %d %q", rec.Code, rec.Body)
	}

	// A flush failure: not credited, error returned.
	f = newFake()
	resp, err := NewServer(WithDownloads(f)).DownloadFile(downloadCtx(t, httptest.NewRequest(http.MethodGet, "/", nil)),
		gen.DownloadFileRequestObject{LinkToken: linkToken, FileId: "fil_1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.VisitDownloadFileResponse(flushFailWriter{httptest.NewRecorder()}); err == nil || f.content.delivered {
		t.Errorf("flush failure: err %v, delivered %v", err, f.content.delivered)
	}

	// A write error: not credited, still closed, error returned.
	f = newFake()
	resp, err = NewServer(WithDownloads(f)).DownloadFile(downloadCtx(t, httptest.NewRequest(http.MethodGet, "/", nil)),
		gen.DownloadFileRequestObject{LinkToken: linkToken, FileId: "fil_1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.VisitDownloadFileResponse(failingWriter{httptest.NewRecorder()}); err == nil {
		t.Error("write error not returned")
	}
	if f.content.delivered || !f.content.closed {
		t.Errorf("after a write error: delivered %v closed %v", f.content.delivered, f.content.closed)
	}

	// Begin is called with the method before a 200 or 206 only.
	if got := fmt.Sprint(f.content.begins); got != "[true]" {
		t.Errorf("begins of a GET = %s", got)
	}
	f = newFake()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Range", "bytes=50-60")
	serveFile(t, f, r)
	if f.content.begins != nil {
		t.Errorf("416: begins %v", f.content.begins)
	}
	f = newFake()
	serveFile(t, f, httptest.NewRequest(http.MethodHead, "/", nil))
	if got := fmt.Sprint(f.content.begins); got != "[false]" {
		t.Errorf("begins of a HEAD = %s", got)
	}

	_, err = NewServer(WithDownloads(&fakeDownloads{err: download.ErrDownloadLocked})).DownloadFile(
		downloadCtx(t, httptest.NewRequest(http.MethodGet, "/", nil)), gen.DownloadFileRequestObject{})
	wantProblem(t, err, problem.CodeDownloadLocked)
}

// TestDownloadFileRefused: a refusal of Begin (download limit) answers its
// Problem, with none of the file headers nor bytes, and closes the content
// without crediting it.
func TestDownloadFileRefused(t *testing.T) {
	t.Parallel()
	for _, rng := range []string{"", "bytes=2-4"} {
		f := &fakeDownloads{name: "plans.pdf", sha: "abc", content: &fakeContent{
			Reader: bytes.NewReader([]byte("0123456789")), begin: download.ErrMaxDownloads,
		}}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if rng != "" {
			r.Header.Set("Range", rng)
		}
		resp, err := NewServer(WithDownloads(f)).DownloadFile(downloadCtx(t, r), gen.DownloadFileRequestObject{LinkToken: linkToken, FileId: "fil_1"})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		wantProblem(t, resp.VisitDownloadFileResponse(rec), problem.CodeMaxDownloadsReached)
		h := rec.Header()
		if rec.Body.Len() != 0 || h.Get("Content-Length") != "" || h.Get("Content-Range") != "" || h.Get("ETag") != "" ||
			h.Get("Content-Disposition") != "" || h.Get("Accept-Ranges") != "" || rec.Flushed {
			t.Errorf("%q: refused answer wrote %q %v", rng, rec.Body, h)
		}
		if f.content.delivered || !f.content.closed {
			t.Errorf("%q: delivered %v closed %v", rng, f.content.delivered, f.content.closed)
		}
	}
}

// flushFailWriter fails the flush.
type flushFailWriter struct{ *httptest.ResponseRecorder }

func (flushFailWriter) FlushError() error { return errors.New("flush failed") }

func TestErrorWriter(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	w := &errorWriter{ResponseWriter: rec}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	w.WriteHeader(http.StatusTeapot) // superfluous: ignored
	if rec.Code != http.StatusOK || w.status != http.StatusOK {
		t.Errorf("implicit 200: %d %d", rec.Code, w.status)
	}
}

func TestRequestMiddlewareScope(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for op, want := range map[string]bool{"DownloadFile": true, "GetDownload": true, "CreateTransfer": false} {
		var got bool
		_, _ = RequestMiddleware(func(ctx context.Context, _ http.ResponseWriter, _ *http.Request, _ any) (any, error) {
			_, got = requestOf(ctx)
			return nil, nil
		}, op)(context.Background(), nil, r, nil)
		if got != want {
			t.Errorf("%s: request in context %v, want %v", op, got, want)
		}
	}
}

// failingWriter fails every write.
type failingWriter struct{ *httptest.ResponseRecorder }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }

func TestErrorWriterUnwrap(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	if (&errorWriter{ResponseWriter: rec}).Unwrap() != rec {
		t.Error("Unwrap does not return the wrapped writer")
	}
}

func TestDownloadArchive(t *testing.T) {
	t.Parallel()
	a := &fakeArchive{data: []byte("PK-zip-bytes")}
	f := &fakeDownloads{archive: a}
	r := withGrant(httptest.NewRequest(http.MethodGet, "/", nil))
	resp, err := NewServer(WithDownloads(f)).DownloadArchive(downloadCtx(t, r), gen.DownloadArchiveRequestObject{LinkToken: linkToken})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitDownloadArchiveResponse(rec); err != nil {
		t.Fatal(err)
	}
	h := rec.Header()
	if rec.Code != http.StatusOK || rec.Body.String() != "PK-zip-bytes" || h.Get("Content-Type") != "application/zip" ||
		h.Get("Content-Length") != "12" || h.Get("Content-Security-Policy") != attachmentCSP || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(h.Get("Content-Disposition"), `attachment; filename="transfer.zip"`) || f.gotGrant != "dg_grant" {
		t.Errorf("archive: %d %q %v", rec.Code, rec.Body, h)
	}
	if !a.closed || !rec.Flushed || f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("archive closed %v, flushed %v, client IP %v", a.closed, rec.Flushed, f.gotIP)
	}

	// A failed flush of the last bytes fails the write (no completion).
	a = &fakeArchive{data: []byte("PK")}
	resp, _ = NewServer(WithDownloads(&fakeDownloads{archive: a})).DownloadArchive(
		downloadCtx(t, httptest.NewRequest(http.MethodGet, "/", nil)), gen.DownloadArchiveRequestObject{})
	if err := resp.VisitDownloadArchiveResponse(flushFailWriter{httptest.NewRecorder()}); err == nil || !a.closed {
		t.Errorf("flush failure: %v, closed %v", err, a.closed)
	}

	// HEAD: headers only.
	a = &fakeArchive{data: []byte("PK")}
	resp, _ = NewServer(WithDownloads(&fakeDownloads{archive: a})).DownloadArchive(
		downloadCtx(t, httptest.NewRequest(http.MethodHead, "/", nil)), gen.DownloadArchiveRequestObject{})
	rec = httptest.NewRecorder()
	if err := resp.VisitDownloadArchiveResponse(rec); err != nil || a.written || !a.closed || rec.Header().Get("Content-Length") != "2" {
		t.Errorf("HEAD archive: %v written %v closed %v %v", err, a.written, a.closed, rec.Header())
	}
	// A write failure is returned (the connection is then aborted).
	a = &fakeArchive{data: []byte("PK"), err: errors.New("disk")}
	resp, _ = NewServer(WithDownloads(&fakeDownloads{archive: a})).DownloadArchive(
		downloadCtx(t, httptest.NewRequest(http.MethodGet, "/", nil)), gen.DownloadArchiveRequestObject{})
	if err := resp.VisitDownloadArchiveResponse(httptest.NewRecorder()); err == nil {
		t.Error("archive failure not returned")
	}

	// A refusal of Begin: its Problem, nothing written.
	a = &fakeArchive{data: []byte("PK"), begin: download.ErrMaxDownloads}
	resp, _ = NewServer(WithDownloads(&fakeDownloads{archive: a})).DownloadArchive(
		downloadCtx(t, httptest.NewRequest(http.MethodHead, "/", nil)), gen.DownloadArchiveRequestObject{})
	rec = httptest.NewRecorder()
	wantProblem(t, resp.VisitDownloadArchiveResponse(rec), problem.CodeMaxDownloadsReached)
	if a.written || !a.closed || rec.Body.Len() != 0 || len(rec.Header()) != 0 || fmt.Sprint(a.begins) != "[false]" {
		t.Errorf("refused archive: written %v closed %v %q %v begins %v", a.written, a.closed, rec.Body, rec.Header(), a.begins)
	}

	_, err = NewServer(WithDownloads(&fakeDownloads{err: download.ErrNotFound})).DownloadArchive(
		downloadCtx(t, httptest.NewRequest(http.MethodGet, "/", nil)), gen.DownloadArchiveRequestObject{})
	wantProblem(t, err, problem.CodeNotFound)
}

func TestAttachment(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"report.pdf":         `attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`,
		"a\\b\x01c.txt":      `attachment; filename="a_b_c.txt"; filename*=UTF-8''a%5Cb%01c.txt`,
		"":                   `attachment; filename="download"; filename*=UTF-8''download`,
		"\xff":               `attachment; filename="download"; filename*=UTF-8''download`,
		"résumé ~!#$&+^`|.x": "attachment; filename=\"r_sum_ ~!#$&+^`|.x\"; filename*=UTF-8''r%C3%A9sum%C3%A9%20~!#$&+^`|.x",
	}
	for name, want := range tests {
		if got := attachment(name); got != want {
			t.Errorf("attachment(%q) = %q, want %q", name, got, want)
		}
	}
}

// FuzzAttachment checks that the Content-Disposition built for any file
// name is a single, pure-ASCII header line whose quoted filename fallback
// cannot be broken out of, and which parses back to the original name.
func FuzzAttachment(f *testing.F) {
	for _, seed := range []string{
		"report.pdf", "", "résumé.txt", `a"b\c.txt`, "line\r\nInjected: 1", "\x00\x7f\xff",
		"\u202etxt.exe", "\U0001F600.png", "%41%22.txt", "a;b=c", "\xc3\x28",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := attachment(name)
		for i := range len(got) {
			if c := got[i]; c == '\r' || c == '\n' || c >= 0x80 {
				t.Fatalf("attachment(%q) = %q: byte %#x at %d", name, got, c, i)
			}
		}
		const prefix, sep = `attachment; filename="`, `"; filename*=UTF-8''`
		rest, ok := strings.CutPrefix(got, prefix)
		fallback, _, found := strings.Cut(rest, sep)
		if !ok || !found {
			t.Fatalf("attachment(%q) = %q: unexpected layout", name, got)
		}
		if strings.ContainsAny(fallback, `"\`) {
			t.Fatalf("attachment(%q): fallback %q holds a quote or a backslash", name, fallback)
		}
		mediaType, params, err := mime.ParseMediaType(got)
		if err != nil || mediaType != "attachment" {
			t.Fatalf("attachment(%q) = %q: parsed %q, %v", name, got, mediaType, err)
		}
		want := name
		if want == "" || !utf8.ValidString(want) {
			want = "download"
		}
		if params["filename"] != want {
			t.Fatalf("attachment(%q) parses back to %q, want %q", name, params["filename"], want)
		}
	})
}

// TestGetDownloadVerification checks the verification fields of the
// download page (since 1.1): the minimal locked view of a link awaiting its
// verification, and the flags of a verified one.
func TestGetDownloadVerification(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 11, 2, 16, 20, 0, 0, time.UTC)
	f := &fakeDownloads{view: download.View{
		SenderEmail: "alice@entity-a.example.com", ExpiresAt: expires, PasswordProtected: true, Locked: true,
		VerificationRequired: true, RecipientEmailMasked: "c***@customer.example.net",
	}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: download.VerificationCookieName, Value: "rv_cookie"})
	resp, err := NewServer(WithDownloads(f)).GetDownload(downloadCtx(t, r), gen.GetDownloadRequestObject{LinkToken: linkToken})
	if err != nil {
		t.Fatal(err)
	}
	got := gen.PublicTransfer(resp.(gen.GetDownload200JSONResponse))
	if f.gotVerification != "rv_cookie" {
		t.Errorf("verification cookie %q", f.gotVerification)
	}
	if !got.Locked || got.VerificationRequired == nil || !*got.VerificationRequired || got.Verified == nil || *got.Verified ||
		got.RecipientEmailMasked == nil || *got.RecipientEmailMasked != "c***@customer.example.net" || !got.PasswordProtected ||
		got.Files != nil || got.Message != nil || got.ArchiveUrl != nil || got.TotalBytes != nil || got.ConfidentialityLevel != nil ||
		got.DownloadsRemaining != nil || got.ReplyAllowed != nil {
		t.Fatalf("awaiting view = %+v", got)
	}
	// Verified and open: the flags, never the masked address.
	f.view = download.View{SenderEmail: "alice@entity-a.example.com", VerificationRequired: true, Verified: true}
	resp, _ = NewServer(WithDownloads(f)).GetDownload(downloadCtx(t, nil), gen.GetDownloadRequestObject{LinkToken: linkToken})
	got = gen.PublicTransfer(resp.(gen.GetDownload200JSONResponse))
	if got.Locked || got.VerificationRequired == nil || !*got.Verified || got.RecipientEmailMasked != nil || got.Files == nil {
		t.Fatalf("verified view = %+v", got)
	}
	// Without the option: no verification field.
	f.view = download.View{SenderEmail: "alice@entity-a.example.com"}
	resp, _ = NewServer(WithDownloads(f)).GetDownload(downloadCtx(t, nil), gen.GetDownloadRequestObject{LinkToken: linkToken})
	got = gen.PublicTransfer(resp.(gen.GetDownload200JSONResponse))
	if got.VerificationRequired != nil || got.Verified != nil || got.RecipientEmailMasked != nil {
		t.Fatalf("view without verification = %+v", got)
	}
}

func TestStartRecipientVerification(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 10, 27, 9, 15, 0, 0, time.UTC)
	f := &fakeDownloads{challenge: &download.Challenge{EmailMasked: "c***@customer.example.net", ExpiresAt: expires, AttemptsRemaining: 2}}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: download.VerificationCookieName, Value: "rv_cookie"})
	lang := "fr-FR"
	resp, err := NewServer(WithDownloads(f)).StartRecipientVerification(downloadCtx(t, r), gen.StartRecipientVerificationRequestObject{
		LinkToken: linkToken, Params: gen.StartRecipientVerificationParams{AcceptLanguage: &lang},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.StartRecipientVerification202JSONResponse)
	if got.EmailMasked != "c***@customer.example.net" || !got.ExpiresAt.Equal(expires) || got.AttemptsRemaining != 2 {
		t.Errorf("challenge = %+v", got)
	}
	if f.gotToken != linkToken || f.gotReply || f.gotLanguage != "fr-FR" || f.gotVerification != "rv_cookie" ||
		f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("service called with %+v", f)
	}
	purpose := func(p gen.RecipientVerificationStartPurpose) *gen.RecipientVerificationStart {
		return &gen.RecipientVerificationStart{Purpose: &p}
	}
	_, _ = NewServer(WithDownloads(f)).StartRecipientVerification(downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{
		Body: purpose(gen.RecipientVerificationStartPurposeDownload),
	})
	if f.gotReply {
		t.Error("download purpose taken as a reply")
	}
	_, _ = NewServer(WithDownloads(f)).StartRecipientVerification(downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{
		Body: purpose(gen.RecipientVerificationStartPurposeReply),
	})
	if !f.gotReply {
		t.Error("reply purpose not passed")
	}
	_, err = NewServer(WithDownloads(f)).StartRecipientVerification(downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{
		Body: purpose("other"),
	})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/purpose" {
		t.Errorf("errors = %+v", p.Errors)
	}
	// The language of the body wins over Accept-Language; an unsupported
	// one is refused.
	for _, c := range []struct{ body, want string }{{"en", "en"}, {"fr", "fr"}} {
		l := gen.Language(c.body)
		_, err = NewServer(WithDownloads(f)).StartRecipientVerification(downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{
			Params: gen.StartRecipientVerificationParams{AcceptLanguage: &lang}, Body: &gen.RecipientVerificationStart{Language: &l},
		})
		if err != nil || f.gotLanguage != c.want {
			t.Errorf("body language %s: %v, service got %q", c.body, err, f.gotLanguage)
		}
	}
	f.gotLanguage = "unset"
	de := gen.Language("de")
	_, err = NewServer(WithDownloads(f)).StartRecipientVerification(downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{
		Body: &gen.RecipientVerificationStart{Language: &de},
	})
	if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/language" || f.gotLanguage != "unset" {
		t.Errorf("errors = %+v, service got %q", p.Errors, f.gotLanguage)
	}
	// Already verified: 204.
	resp, err = NewServer(WithDownloads(&fakeDownloads{})).StartRecipientVerification(downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{})
	if _, ok := resp.(gen.StartRecipientVerification204Response); !ok || err != nil {
		t.Errorf("verified = %T, %v", resp, err)
	}
	_, err = NewServer(WithDownloads(&fakeDownloads{err: &download.RateLimitError{RetryAfter: time.Hour}})).StartRecipientVerification(
		downloadCtx(t, nil), gen.StartRecipientVerificationRequestObject{})
	wantProblem(t, err, problem.CodeRateLimited)
}

func TestConfirmRecipientVerification(t *testing.T) {
	t.Parallel()
	f := &fakeDownloads{cookie: "rv_new"}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: download.VerificationCookieName, Value: "rv_old"})
	resp, err := NewServer(WithDownloads(f)).ConfirmRecipientVerification(downloadCtx(t, r), gen.ConfirmRecipientVerificationRequestObject{
		LinkToken: linkToken, Body: &gen.VerificationCode{Code: "482913"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.ConfirmRecipientVerification204Response)
	want := "__Host-tt_rv=rv_new; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict"
	if got.Headers.SetCookie == nil || *got.Headers.SetCookie != want {
		t.Errorf("Set-Cookie = %v, want %q", got.Headers.SetCookie, want)
	}
	if f.gotCode != "482913" || f.gotVerification != "rv_old" || f.gotToken != linkToken || f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("service called with %+v", f)
	}
	for _, body := range []*gen.VerificationCode{nil, {}} {
		_, err = NewServer(WithDownloads(f)).ConfirmRecipientVerification(downloadCtx(t, nil),
			gen.ConfirmRecipientVerificationRequestObject{Body: body})
		if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/code" || p.Errors[0].Code != "required" {
			t.Errorf("errors = %+v", p.Errors)
		}
	}
	_, err = NewServer(WithDownloads(&fakeDownloads{err: &download.WrongCodeError{Remaining: 1}})).ConfirmRecipientVerification(
		downloadCtx(t, nil), gen.ConfirmRecipientVerificationRequestObject{Body: &gen.VerificationCode{Code: "000000"}})
	if p := problemOf(t, err, problem.CodeVerificationCodeInvalid); p.Status != http.StatusUnprocessableEntity || *p.AttemptsRemaining != 1 {
		t.Errorf("wrong code = %+v", p)
	}
}

// TestVerificationRequiredOnStreams: a file or archive of a link awaiting
// its verification is the recipient-verification-required Problem.
func TestVerificationRequiredOnStreams(t *testing.T) {
	t.Parallel()
	f := &fakeDownloads{err: download.ErrVerificationRequired}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := NewServer(WithDownloads(f)).DownloadFile(downloadCtx(t, r), gen.DownloadFileRequestObject{LinkToken: linkToken, FileId: "fil_1"})
	if p := problemOf(t, err, problem.CodeRecipientVerificationRequired); p.Status != http.StatusUnauthorized {
		t.Errorf("file = %+v", p)
	}
	_, err = NewServer(WithDownloads(f)).DownloadArchive(downloadCtx(t, r), gen.DownloadArchiveRequestObject{LinkToken: linkToken})
	wantProblem(t, err, problem.CodeRecipientVerificationRequired)
	_, err = NewServer(WithDownloads(f)).UnlockDownload(downloadCtx(t, nil), gen.UnlockDownloadRequestObject{
		Body: &gen.TransferPassword{Password: "x"},
	})
	wantProblem(t, err, problem.CodeRecipientVerificationRequired)
}

func TestReportAbuse(t *testing.T) {
	t.Parallel()
	f := &fakeDownloads{}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: download.VerificationCookieName, Value: "rv_raw"})
	msg := "this is a phishing mail"
	resp, err := NewServer(WithDownloads(f)).ReportAbuse(downloadCtx(t, r), gen.ReportAbuseRequestObject{
		LinkToken: linkToken, Body: &gen.AbuseReportCreate{Category: gen.Phishing, Message: &msg},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.(gen.ReportAbuse202Response); !ok {
		t.Errorf("response = %T", resp)
	}
	if f.gotToken != linkToken || f.gotVerification != "rv_raw" || f.gotCategory != "phishing" || f.gotMessage != msg ||
		f.gotIP != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("service called with %+v", f)
	}
	// The message is optional.
	f = &fakeDownloads{}
	if _, err := NewServer(WithDownloads(f)).ReportAbuse(downloadCtx(t, nil), gen.ReportAbuseRequestObject{
		LinkToken: linkToken, Body: &gen.AbuseReportCreate{Category: gen.Spam},
	}); err != nil || f.gotMessage != "" || f.gotCategory != "spam" {
		t.Errorf("without message: %v %+v", err, f)
	}
	for name, body := range map[string]*gen.AbuseReportCreate{"no body": nil, "no category": {}} {
		_, err = NewServer(WithDownloads(f)).ReportAbuse(downloadCtx(t, nil), gen.ReportAbuseRequestObject{Body: body})
		if p := problemOf(t, err, problem.CodeValidationFailed); p.Errors[0].Field != "/category" || p.Errors[0].Code != "required" {
			t.Errorf("%s: errors = %+v", name, p.Errors)
		}
	}
}

func TestReportAbuseErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err   error
		code  problem.Code
		field string
	}{
		{download.ErrInvalidCategory, problem.CodeValidationFailed, "/category"},
		{download.ErrInvalidMessage, problem.CodeValidationFailed, "/message"},
		{download.ErrNotFound, problem.CodeNotFound, ""},
		{download.ErrGone, problem.CodeTransferGone, ""},
		{&download.RateLimitError{RetryAfter: 30 * time.Second}, problem.CodeRateLimited, ""},
	} {
		_, err := NewServer(WithDownloads(&fakeDownloads{err: tc.err})).ReportAbuse(downloadCtx(t, nil), gen.ReportAbuseRequestObject{
			LinkToken: linkToken, Body: &gen.AbuseReportCreate{Category: gen.Other},
		})
		p := problemOf(t, err, tc.code)
		if tc.field != "" && p.Errors[0].Field != tc.field {
			t.Errorf("%v: errors = %+v", tc.err, p.Errors)
		}
		if tc.code == problem.CodeRateLimited && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 30) {
			t.Errorf("retry after = %v", p.RetryAfterSeconds)
		}
	}
}

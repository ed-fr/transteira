package public

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
)

var (
	expires    = time.Date(2026, 10, 19, 20, 0, 0, 0, time.UTC)
	invExpires = time.Date(2027, 10, 19, 16, 0, 0, 0, time.UTC)
)

// internalInfo is the session of an internal depositor.
func internalInfo() deposit.SessionInfo {
	return deposit.SessionInfo{
		ID: "ds_secret_record", Email: "alice@entity-a.example.com", Kind: deposit.KindInternal,
		ExpiresAt: expires, CanInvite: true, CSRFToken: "csrf_abc",
		Limits: deposit.Limits{MaxTransferBytes: 21474836480, ExpiryDays: []int{1, 7, 30}},
	}
}

// externalInfo is the session of an invited depositor.
func externalInfo() deposit.SessionInfo {
	info := internalInfo()
	info.Email, info.Kind, info.CanInvite = "bob@partner.example.org", deposit.KindExternal, false
	info.Invitation = &deposit.InvitationInfo{ID: "inv_secret_record", InvitedBy: "alice@entity-a.example.com", ExpiresAt: invExpires}
	return info
}

// fakeDeposit records its calls and answers with the configured values.
type fakeDeposit struct {
	err    error
	result deposit.Result
	inv    deposit.PublicInvitation

	gotIP        netip.Addr
	gotLang      string
	gotEmail     string
	gotToken     string
	gotCode      string
	gotMessage   string
	gotLanguage  string
	gotSessionID string
	gotRecog     string
	recognition  string // returned in Session.Recognition by Confirm

	// replySession is the answer of OpenReply, gotTarget what it received.
	replySession deposit.Session
	gotTarget    deposit.ReplyTarget
}

func (f *fakeDeposit) Start(_ context.Context, _ *tenant.Tenant, ip netip.Addr, lang, email, inv, recog string) (deposit.Result, error) {
	f.gotIP, f.gotLang, f.gotEmail, f.gotToken, f.gotRecog = ip, lang, email, inv, recog
	return f.result, f.err
}

func (f *fakeDeposit) Confirm(_ context.Context, _ *tenant.Tenant, ip netip.Addr, chID, code, recog string) (deposit.Session, error) {
	f.gotIP, f.gotToken, f.gotCode, f.gotRecog = ip, chID, code, recog
	if f.err != nil {
		return deposit.Session{}, f.err
	}
	return deposit.Session{Token: "ds_new", Recognition: f.recognition, SessionInfo: externalInfo()}, nil
}

func (f *fakeDeposit) End(_ context.Context, _ *tenant.Tenant, raw string) error {
	f.gotToken = raw
	return f.err
}

func (f *fakeDeposit) Invite(_ context.Context, _ *tenant.Tenant, s deposit.SessionInfo, ip netip.Addr, lang, email, msg, language string) (deposit.Invitation, error) {
	f.gotSessionID, f.gotIP, f.gotLang, f.gotEmail, f.gotMessage, f.gotLanguage = s.ID, ip, lang, email, msg, language
	if f.err != nil {
		return deposit.Invitation{}, f.err
	}
	return deposit.Invitation{
		ID: "inv_01JABCF0Z9Y8X7W6V5V4T3S2R1", Email: email, InvitedBy: s.Email, Status: deposit.InvitationPending,
		Language: "en", CreatedAt: expires, ExpiresAt: invExpires,
	}, nil
}

func (f *fakeDeposit) PublicInvitation(_ context.Context, _ *tenant.Tenant, raw string) (deposit.PublicInvitation, error) {
	f.gotToken = raw
	return f.inv, f.err
}

// depositCtx returns a context with tenant A, a client IP and, when info
// is not nil, a deposit session set by the middleware.
func depositCtx(t *testing.T, info *deposit.SessionInfo) context.Context {
	t.Helper()
	ctx := tenantCtx()
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	r.RemoteAddr = "192.0.2.7:1234"
	var captured context.Context
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { captured = r.Context() })
	chain := middleware.RealIP(nil)(h)
	if info != nil {
		r.AddCookie(&http.Cookie{Name: middleware.DepositCookie, Value: "ds_raw"})
		chain = middleware.RealIP(nil)(middleware.DepositSession(staticSessions{info: *info}, func(*http.Request) bool { return true }, nil)(h))
	}
	chain.ServeHTTP(httptest.NewRecorder(), r)
	if captured == nil {
		t.Fatal("middleware chain did not reach the handler")
	}
	return captured
}

// staticSessions resolves every token to info.
type staticSessions struct{ info deposit.SessionInfo }

func (s staticSessions) ResolveSession(context.Context, string) (any, bool, error) {
	return s.info, true, nil
}
func (staticSessions) CheckCSRF(string, string) bool { return true }

func newDepositServer(f *fakeDeposit) *Server {
	s := NewServer(WithDeposit(f))
	// Four hours before the sessions of the fixtures expire.
	s.now = func() time.Time { return expires.Add(-4 * time.Hour) }
	return s
}

// visitor renders the responses of both session-creating operations.
type visitor interface {
	VisitStartDepositSessionResponse(http.ResponseWriter) error
	VisitConfirmVerificationChallengeResponse(http.ResponseWriter) error
}

// render writes resp with the start (or, with confirm, the confirmation)
// visitor and returns the recorded response.
func render(t *testing.T, resp any, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	v, ok := resp.(visitor)
	if !ok {
		t.Fatalf("response %T does not render a 201 session", resp)
	}
	rec := httptest.NewRecorder()
	visit := v.VisitStartDepositSessionResponse
	if confirm {
		visit = v.VisitConfirmVerificationChallengeResponse
	}
	if err := visit(rec); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusCreated || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	return rec
}

// decodeSession decodes a DepositSession body.
func decodeSession(t *testing.T, rec *httptest.ResponseRecorder) gen.DepositSession {
	t.Helper()
	var s gen.DepositSession
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// problemOf asserts err is a Problem with code and returns it.
func problemOf(t *testing.T, err error, code problem.Code) *problem.Problem {
	t.Helper()
	var p *problem.Problem
	if !errors.As(err, &p) || p.Code != code {
		t.Fatalf("error = %v, want problem %s", err, code)
	}
	return p
}

// wantProblem asserts err is a Problem with code.
func wantProblem(t *testing.T, err error, code problem.Code) {
	t.Helper()
	if p := problemOf(t, err, code); p == nil {
		t.Fatal("nil problem")
	}
}

func TestDepositOperationsRequireTenantAndService(t *testing.T) {
	t.Parallel()
	bare := NewServer()
	srv := newDepositServer(&fakeDeposit{})
	body := &gen.DepositSessionStart{Email: "alice@entity-a.example.com"}
	calls := map[string]func(*Server, context.Context) error{
		"start": func(s *Server, ctx context.Context) error {
			_, err := s.StartDepositSession(ctx, gen.StartDepositSessionRequestObject{Body: body})
			return err
		},
		"confirm": func(s *Server, ctx context.Context) error {
			_, err := s.ConfirmVerificationChallenge(ctx, gen.ConfirmVerificationChallengeRequestObject{})
			return err
		},
		"current": func(s *Server, ctx context.Context) error {
			_, err := s.GetCurrentDepositSession(ctx, gen.GetCurrentDepositSessionRequestObject{})
			return err
		},
		"end": func(s *Server, ctx context.Context) error {
			_, err := s.EndDepositSession(ctx, gen.EndDepositSessionRequestObject{})
			return err
		},
		"invite": func(s *Server, ctx context.Context) error {
			_, err := s.CreateInvitation(ctx, gen.CreateInvitationRequestObject{})
			return err
		},
		"getInvitation": func(s *Server, ctx context.Context) error {
			_, err := s.GetInvitation(ctx, gen.GetInvitationRequestObject{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, call(srv, context.Background()), problem.CodeUnknownTenant)
			if name == "current" {
				return // served from the session alone
			}
			if err := call(bare, tenantCtx()); !errors.Is(err, errNoDepositService) {
				t.Errorf("without deposit service: %v, want errNoDepositService", err)
			}
		})
	}
}

func TestStartDepositSession(t *testing.T) {
	t.Parallel()
	lang := "fr-FR,fr;q=0.9"
	tok := "inv_9sK2mQ7xL0aZ4vR8tYb3nC6dE1fG5hJ"

	t.Run("session", func(t *testing.T) {
		t.Parallel()
		info := internalInfo()
		f := &fakeDeposit{result: deposit.Result{Session: &deposit.Session{Token: "ds_tok", Recognition: "mac1.mac2", SessionInfo: info}}}
		recog := "mac2"
		resp, err := newDepositServer(f).StartDepositSession(depositCtx(t, nil), gen.StartDepositSessionRequestObject{
			Params: gen.StartDepositSessionParams{AcceptLanguage: &lang, UnderscoreUnderscoreHostTtKnown: &recog},
			Body:   &gen.DepositSessionStart{Email: "alice@entity-a.example.com", InvitationToken: &tok},
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := render(t, resp, false)
		want := []string{
			"__Host-tt_deposit=ds_tok; Path=/; Max-Age=14400; HttpOnly; Secure; SameSite=Strict",
			"__Host-tt_known=mac1.mac2; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict",
		}
		if got := rec.Header().Values("Set-Cookie"); !slices.Equal(got, want) {
			t.Errorf("Set-Cookie = %q, want %q", got, want)
		}
		if f.gotRecog != recog {
			t.Errorf("recognition passed %q, want %q", f.gotRecog, recog)
		}
		got := struct{ Body gen.DepositSession }{decodeSession(t, rec)}
		if got.Body.Email != "alice@entity-a.example.com" || got.Body.Kind != "internal" || got.Body.CsrfToken != "csrf_abc" ||
			!got.Body.CanInvite || got.Body.Invitation != nil || got.Body.Limits.MaxTransferBytes != 21474836480 ||
			fmt.Sprint(got.Body.Limits.ExpiryDays) != "[1 7 30]" || !got.Body.ExpiresAt.Equal(expires) {
			t.Errorf("body = %+v", got.Body)
		}
		if f.gotIP != netip.MustParseAddr("192.0.2.7") || f.gotLang != lang || f.gotEmail != "alice@entity-a.example.com" || f.gotToken != tok {
			t.Errorf("service called with ip %v lang %q email %q token %q", f.gotIP, f.gotLang, f.gotEmail, f.gotToken)
		}
	})

	t.Run("challenge", func(t *testing.T) {
		t.Parallel()
		ch := &deposit.Challenge{ID: "vch_x", Email: "alice@entity-a.example.com", ExpiresAt: expires, AttemptsRemaining: 2}
		f := &fakeDeposit{result: deposit.Result{Challenge: ch}}
		resp, err := newDepositServer(f).StartDepositSession(depositCtx(t, nil), gen.StartDepositSessionRequestObject{
			Body: &gen.DepositSessionStart{Email: "alice@entity-a.example.com"},
		})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := resp.(gen.StartDepositSession202JSONResponse)
		if !ok {
			t.Fatalf("response %T", resp)
		}
		if got.ChallengeId != "vch_x" || got.Email != "alice@entity-a.example.com" || got.AttemptsRemaining != 2 || !got.ExpiresAt.Equal(expires) {
			t.Errorf("challenge = %+v", got)
		}
		if f.gotLang != "" || f.gotToken != "" || f.gotRecog != "" {
			t.Errorf("lang %q token %q recognition %q, want empty", f.gotLang, f.gotToken, f.gotRecog)
		}
	})

	t.Run("no body", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{}).StartDepositSession(depositCtx(t, nil), gen.StartDepositSessionRequestObject{})
		p := problemOf(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Field != "/email" || p.Errors[0].Code != "required" {
			t.Errorf("errors = %+v", p.Errors)
		}
	})

	t.Run("empty result", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{}).StartDepositSession(depositCtx(t, nil), gen.StartDepositSessionRequestObject{
			Body: &gen.DepositSessionStart{Email: "alice@entity-a.example.com"},
		})
		if err == nil || problem.From(err).Code != problem.CodeInternalError {
			t.Errorf("error = %v, want an internal error", err)
		}
	})

	t.Run("service error", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{err: deposit.ErrForbidden}).StartDepositSession(depositCtx(t, nil),
			gen.StartDepositSessionRequestObject{Body: &gen.DepositSessionStart{Email: "x@example.com"}})
		wantProblem(t, err, problem.CodeDepositNotAllowed)
	})
}

func TestConfirmVerificationChallenge(t *testing.T) {
	t.Parallel()
	t.Run("session", func(t *testing.T) {
		t.Parallel()
		f := &fakeDeposit{}
		resp, err := newDepositServer(f).ConfirmVerificationChallenge(depositCtx(t, nil), gen.ConfirmVerificationChallengeRequestObject{
			ChallengeId: "vch_x", Body: &gen.VerificationCode{Code: "482913"},
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := render(t, resp, true)
		// An external depositor's recognition cookie is left alone.
		if got := rec.Header().Values("Set-Cookie"); len(got) != 1 || !strings.HasPrefix(got[0], "__Host-tt_deposit=ds_new; Path=/; Max-Age=14400") {
			t.Errorf("Set-Cookie = %q", got)
		}
		got := struct{ Body gen.DepositSession }{decodeSession(t, rec)}
		if got.Body.Kind != "external" || got.Body.CanInvite || got.Body.Invitation == nil ||
			got.Body.Invitation.InvitedBy != "alice@entity-a.example.com" || !got.Body.Invitation.ExpiresAt.Equal(invExpires) {
			t.Errorf("body = %+v", got.Body)
		}
		if f.gotToken != "vch_x" || f.gotCode != "482913" || !f.gotIP.IsValid() {
			t.Errorf("called with %q %q %v", f.gotToken, f.gotCode, f.gotIP)
		}
	})
	t.Run("no body", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{}).ConfirmVerificationChallenge(depositCtx(t, nil),
			gen.ConfirmVerificationChallengeRequestObject{ChallengeId: "vch_x"})
		p := problemOf(t, err, problem.CodeValidationFailed)
		if p.Errors[0].Field != deposit.FieldCode {
			t.Errorf("errors = %+v", p.Errors)
		}
	})
	t.Run("wrong code", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{err: &deposit.WrongCodeError{Remaining: 1}}).ConfirmVerificationChallenge(
			depositCtx(t, nil), gen.ConfirmVerificationChallengeRequestObject{ChallengeId: "vch_x", Body: &gen.VerificationCode{Code: "000000"}})
		p := problemOf(t, err, problem.CodeVerificationCodeInvalid)
		if p.AttemptsRemaining == nil || *p.AttemptsRemaining != 1 {
			t.Errorf("attemptsRemaining = %v", p.AttemptsRemaining)
		}
	})
}

func TestGetCurrentDepositSession(t *testing.T) {
	t.Parallel()
	info := externalInfo()
	resp, err := NewServer().GetCurrentDepositSession(depositCtx(t, &info), gen.GetCurrentDepositSessionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resp.(gen.GetCurrentDepositSession200JSONResponse)
	if !ok {
		t.Fatalf("response %T", resp)
	}
	if got.Email != "bob@partner.example.org" || got.CsrfToken != "csrf_abc" || got.Invitation == nil {
		t.Errorf("body = %+v", got)
	}
	// Without the session middleware the request is unauthenticated.
	_, err = NewServer().GetCurrentDepositSession(depositCtx(t, nil), gen.GetCurrentDepositSessionRequestObject{})
	wantProblem(t, err, problem.CodeUnauthenticated)
}

func TestEndDepositSession(t *testing.T) {
	t.Parallel()
	info := internalInfo()
	f := &fakeDeposit{}
	resp, err := newDepositServer(f).EndDepositSession(depositCtx(t, &info), gen.EndDepositSessionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resp.(gen.EndDepositSession204Response)
	if !ok {
		t.Fatalf("response %T", resp)
	}
	want := "__Host-tt_deposit=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
	if got.Headers.SetCookie == nil || *got.Headers.SetCookie != want {
		t.Errorf("Set-Cookie = %v, want %q", got.Headers.SetCookie, want)
	}
	if f.gotToken != "ds_raw" {
		t.Errorf("ended token %q", f.gotToken)
	}

	_, err = newDepositServer(&fakeDeposit{}).EndDepositSession(depositCtx(t, nil), gen.EndDepositSessionRequestObject{})
	wantProblem(t, err, problem.CodeUnauthenticated)

	_, err = newDepositServer(&fakeDeposit{err: deposit.ErrUnauthenticated}).EndDepositSession(depositCtx(t, &info), gen.EndDepositSessionRequestObject{})
	wantProblem(t, err, problem.CodeUnauthenticated)
}

func TestCreateInvitation(t *testing.T) {
	t.Parallel()
	internal, external := internalInfo(), externalInfo()
	msg, lang, accept := "Please send me the signed contract.", gen.Language("en"), "fr"
	body := &gen.InvitationCreate{Email: "bob@partner.example.org", Message: &msg, Language: &lang}

	t.Run("created", func(t *testing.T) {
		t.Parallel()
		f := &fakeDeposit{}
		resp, err := newDepositServer(f).CreateInvitation(depositCtx(t, &internal), gen.CreateInvitationRequestObject{
			Params: gen.CreateInvitationParams{AcceptLanguage: &accept}, Body: body,
		})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := resp.(gen.CreateInvitation201JSONResponse)
		if !ok {
			t.Fatalf("response %T", resp)
		}
		if got.Id != "inv_01JABCF0Z9Y8X7W6V5V4T3S2R1" || got.Email != "bob@partner.example.org" || got.InvitedBy != "alice@entity-a.example.com" ||
			got.Status != "pending" || !got.CreatedAt.Equal(expires) || !got.ExpiresAt.Equal(invExpires) || got.LastUsedAt != nil {
			t.Errorf("body = %+v", got)
		}
		if f.gotSessionID != internal.ID || f.gotLang != accept || f.gotMessage != msg || f.gotLanguage != "en" || !f.gotIP.IsValid() {
			t.Errorf("service called with %+v", f)
		}
	})
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		f := &fakeDeposit{}
		if _, err := newDepositServer(f).CreateInvitation(depositCtx(t, &internal), gen.CreateInvitationRequestObject{
			Body: &gen.InvitationCreate{Email: "bob@partner.example.org"},
		}); err != nil {
			t.Fatal(err)
		}
		if f.gotMessage != "" || f.gotLanguage != "" || f.gotLang != "" {
			t.Errorf("message %q language %q accept %q, want empty", f.gotMessage, f.gotLanguage, f.gotLang)
		}
	})
	t.Run("external", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{}).CreateInvitation(depositCtx(t, &external), gen.CreateInvitationRequestObject{Body: body})
		wantProblem(t, err, problem.CodeInvitationNotAllowed)
	})
	t.Run("no session", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{}).CreateInvitation(depositCtx(t, nil), gen.CreateInvitationRequestObject{Body: body})
		wantProblem(t, err, problem.CodeUnauthenticated)
	})
	t.Run("no body", func(t *testing.T) {
		t.Parallel()
		_, err := newDepositServer(&fakeDeposit{}).CreateInvitation(depositCtx(t, &internal), gen.CreateInvitationRequestObject{})
		wantProblem(t, err, problem.CodeValidationFailed)
	})
	t.Run("mail unavailable", func(t *testing.T) {
		t.Parallel()
		cause := fmt.Errorf("%w: the tenant has no smtp settings", deposit.ErrMailUnavailable)
		_, err := newDepositServer(&fakeDeposit{err: cause}).CreateInvitation(depositCtx(t, &internal), gen.CreateInvitationRequestObject{Body: body})
		wantProblem(t, err, problem.CodeMailUnavailable)
		if !strings.Contains(err.Error(), "no smtp settings") {
			t.Errorf("error %q lost its cause", err)
		}
	})
}

func TestGetInvitation(t *testing.T) {
	t.Parallel()
	f := &fakeDeposit{inv: deposit.PublicInvitation{
		Email: "bob@partner.example.org", InvitedBy: "alice@entity-a.example.com", Message: "Hello", ExpiresAt: invExpires,
	}}
	resp, err := newDepositServer(f).GetInvitation(depositCtx(t, nil), gen.GetInvitationRequestObject{InvitationToken: "inv_tok"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resp.(gen.GetInvitation200JSONResponse)
	if !ok {
		t.Fatalf("response %T", resp)
	}
	if got.Email != "bob@partner.example.org" || got.InvitedBy != "alice@entity-a.example.com" || got.Message == nil ||
		*got.Message != "Hello" || !got.ExpiresAt.Equal(invExpires) || f.gotToken != "inv_tok" {
		t.Errorf("body = %+v", got)
	}

	f.inv.Message = ""
	resp, err = newDepositServer(f).GetInvitation(depositCtx(t, nil), gen.GetInvitationRequestObject{InvitationToken: "inv_tok"})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.(gen.GetInvitation200JSONResponse); got.Message != nil {
		t.Errorf("message = %q, want none", *got.Message)
	}

	_, err = newDepositServer(&fakeDeposit{err: deposit.ErrInvitationGone}).GetInvitation(depositCtx(t, nil), gen.GetInvitationRequestObject{})
	wantProblem(t, err, problem.CodeInvitationGone)
}

func TestDepositError(t *testing.T) {
	t.Parallel()
	internal := errors.New("disk full")
	tests := []struct {
		name  string
		err   error
		code  problem.Code
		check func(t *testing.T, p *problem.Problem)
	}{
		{
			name: "invalid email", err: fmt.Errorf("wrap: %w", &deposit.InvalidError{Field: deposit.FieldEmail}), code: problem.CodeValidationFailed,
			check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if len(p.Errors) != 1 || p.Errors[0].Field != "/email" || p.Errors[0].Code != "invalid-email" {
					t.Errorf("errors = %+v", p.Errors)
				}
			},
		},
		{
			name: "invalid message", err: &deposit.InvalidError{Field: deposit.FieldMessage}, code: problem.CodeValidationFailed,
			check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if p.Errors[0].Field != "/message" || p.Errors[0].Code != "invalid-format" {
					t.Errorf("errors = %+v", p.Errors)
				}
			},
		},
		{name: "wrong code", err: &deposit.WrongCodeError{Remaining: 1}, code: problem.CodeVerificationCodeInvalid},
		{
			name: "rate limited", err: &deposit.RateLimitError{RetryAfter: 90 * time.Second}, code: problem.CodeRateLimited,
			check: func(t *testing.T, p *problem.Problem) {
				t.Helper()
				if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 90 {
					t.Errorf("retryAfterSeconds = %v", p.RetryAfterSeconds)
				}
			},
		},
		{name: "unauthenticated", err: deposit.ErrUnauthenticated, code: problem.CodeUnauthenticated},
		{name: "forbidden", err: deposit.ErrForbidden, code: problem.CodeDepositNotAllowed},
		{name: "reply gone", err: deposit.ErrReplyGone, code: problem.CodeTransferGone},
		{name: "not found", err: deposit.ErrNotFound, code: problem.CodeNotFound},
		{name: "invitation gone", err: deposit.ErrInvitationGone, code: problem.CodeInvitationGone},
		{name: "challenge gone", err: deposit.ErrChallengeGone, code: problem.CodeVerificationExhausted},
		{name: "mail unavailable", err: deposit.ErrMailUnavailable, code: problem.CodeMailUnavailable},
		{name: "internal", err: internal, code: problem.CodeInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := depositError(tt.err)
			p := problem.From(got)
			if p.Code != tt.code {
				t.Fatalf("code = %s, want %s", p.Code, tt.code)
			}
			if tt.check != nil {
				tt.check(t, p)
			}
			if tt.code == problem.CodeInternalError && !errors.Is(got, internal) {
				t.Errorf("internal error not passed through: %v", got)
			}
		})
	}
}

func TestConfirmSetsRecognitionCookie(t *testing.T) {
	t.Parallel()
	f := &fakeDeposit{recognition: "macA"}
	recog := "old"
	resp, err := newDepositServer(f).ConfirmVerificationChallenge(depositCtx(t, nil), gen.ConfirmVerificationChallengeRequestObject{
		ChallengeId: "vch_x", Params: gen.ConfirmVerificationChallengeParams{UnderscoreUnderscoreHostTtKnown: &recog},
		Body: &gen.VerificationCode{Code: "482913"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := render(t, resp, true).Header().Values("Set-Cookie")
	if len(got) != 2 || got[1] != "__Host-tt_known=macA; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict" {
		t.Errorf("Set-Cookie = %q", got)
	}
	for _, c := range got {
		if strings.Contains(strings.ToLower(c), "domain=") {
			t.Errorf("cookie %q has a Domain attribute", c)
		}
	}
	if f.gotRecog != recog {
		t.Errorf("recognition passed %q", f.gotRecog)
	}
}

func TestSessionCookieMaxAge(t *testing.T) {
	t.Parallel()
	s := NewServer()
	s.now = func() time.Time { return expires.Add(-90*time.Minute - 500*time.Millisecond) }
	sess := deposit.Session{Token: "ds_t", SessionInfo: deposit.SessionInfo{ExpiresAt: expires}}
	if got := s.sessionCookies(sess); len(got) != 1 || !strings.Contains(got[0], "Max-Age=5400;") {
		t.Errorf("cookies = %q, want Max-Age=5400 from the session expiry", got)
	}
	// An already expired session never yields Max-Age=0, which would delete
	// the cookie instead of setting it.
	s.now = func() time.Time { return expires.Add(time.Minute) }
	if got := s.sessionCookies(sess); !strings.Contains(got[0], "Max-Age=1;") {
		t.Errorf("cookies = %q, want Max-Age=1", got)
	}
}

func TestSessionCreatedEncodeError(t *testing.T) {
	t.Parallel()
	// A year beyond 9999 cannot be encoded as RFC 3339.
	r := sessionCreated{body: gen.DepositSession{ExpiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}}
	rec := httptest.NewRecorder()
	if err := r.VisitStartDepositSessionResponse(rec); err == nil {
		t.Fatal("encoding error not reported")
	}
	if rec.Header().Get("Set-Cookie") != "" || rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("something was written before the encoding failed: %d %q", rec.Code, rec.Body)
	}
}

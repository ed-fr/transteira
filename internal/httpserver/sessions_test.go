package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
)

const (
	goodToken = "ds_good"
	goodCSRF  = "csrf_good"
)

// fakeSessions knows the session goodToken of tenant ten_a.
type fakeSessions struct {
	err error
}

func (f fakeSessions) Session(_ context.Context, t *tenant.Tenant, raw string) (deposit.SessionInfo, error) {
	if f.err != nil {
		return deposit.SessionInfo{}, f.err
	}
	if t.ID != "ten_a" || raw != goodToken {
		return deposit.SessionInfo{}, deposit.ErrUnauthenticated
	}
	return deposit.SessionInfo{
		ID: "ds_secret", Email: "alice@entity-a.example.com", Kind: deposit.KindInternal, CanInvite: true,
		CSRFToken: goodCSRF, ExpiresAt: time.Date(2026, 10, 19, 20, 0, 0, 0, time.UTC),
		Limits: deposit.Limits{MaxTransferBytes: 1 << 30, ExpiryDays: []int{1, 7, 30}},
	}, nil
}

func (fakeSessions) CheckCSRF(raw, header string) bool { return raw == goodToken && header == goodCSRF }

// fakeDeposit is a deposit service whose End and Invite succeed.
type fakeDeposit struct {
	public.DepositService
	ended []string
}

func (f *fakeDeposit) End(_ context.Context, _ *tenant.Tenant, raw string) error {
	f.ended = append(f.ended, raw)
	return nil
}

func (f *fakeDeposit) Invite(_ context.Context, _ *tenant.Tenant, s deposit.SessionInfo, _ netip.Addr, _, email, _, _ string) (deposit.Invitation, error) {
	return deposit.Invitation{ID: "inv_01", Email: email, InvitedBy: s.Email, Status: deposit.InvitationPending}, nil
}

func (f *fakeDeposit) Start(_ context.Context, _ *tenant.Tenant, _ netip.Addr, _, email, _, recognition string) (deposit.Result, error) {
	if recognition != "mac_alice" {
		return deposit.Result{Challenge: &deposit.Challenge{ID: "vch_x", Email: email, AttemptsRemaining: 2}}, nil
	}
	return deposit.Result{Session: &deposit.Session{
		Token: goodToken, Recognition: "mac_alice.mac_other",
		SessionInfo: deposit.SessionInfo{ID: "ds_secret", Email: email, Kind: deposit.KindInternal, ExpiresAt: time.Now().Add(time.Hour)},
	}}, nil
}

func newSessionEnv(t *testing.T, sessions DepositSessions) (*env, *fakeDeposit) {
	t.Helper()
	dep := &fakeDeposit{}
	return newEnv(t, envConfig{api: public.NewServer(public.WithDeposit(dep)), sessions: sessions}), dep
}

func TestDepositSessionRoutes(t *testing.T) {
	t.Parallel()
	cookie := middleware.DepositCookie + "=" + goodToken
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		hdr    []string
		status int
		code   problem.Code
	}{
		{
			name: "current without cookie", method: http.MethodGet, path: "/api/v1/deposit-sessions/current",
			status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{
			name: "current with unknown cookie", method: http.MethodGet, path: "/api/v1/deposit-sessions/current",
			hdr: []string{"Cookie", middleware.DepositCookie + "=ds_other"}, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{
			name: "current", method: http.MethodGet, path: "/api/v1/deposit-sessions/current",
			hdr: []string{"Cookie", cookie}, status: http.StatusOK,
		},
		{
			name: "end without csrf", method: http.MethodDelete, path: "/api/v1/deposit-sessions/current",
			hdr: []string{"Cookie", cookie}, status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "end with foreign origin", method: http.MethodDelete, path: "/api/v1/deposit-sessions/current",
			hdr:    []string{"Cookie", cookie, middleware.HeaderCSRFToken, goodCSRF, "Origin", "https://evil.example.net"},
			status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "end without cookie", method: http.MethodDelete, path: "/api/v1/deposit-sessions/current",
			hdr: []string{middleware.HeaderCSRFToken, goodCSRF}, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{
			name: "end", method: http.MethodDelete, path: "/api/v1/deposit-sessions/current",
			hdr:    []string{"Cookie", cookie, middleware.HeaderCSRFToken, goodCSRF, "Origin", "https://" + hostA, "Sec-Fetch-Site", "same-origin"},
			status: http.StatusNoContent,
		},
		{
			name: "invite without csrf", method: http.MethodPost, path: "/api/v1/invitations", body: `{"email":"bob@partner.example.org"}`,
			hdr: []string{"Cookie", cookie, "Content-Type", "application/json"}, status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "invite unauthenticated before media type", method: http.MethodPost, path: "/api/v1/invitations", body: `x`,
			hdr: []string{"Content-Type", "text/plain"}, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{
			name: "invite", method: http.MethodPost, path: "/api/v1/invitations", body: `{"email":"bob@partner.example.org"}`,
			hdr:    []string{"Cookie", cookie, "Content-Type", "application/json", middleware.HeaderCSRFToken, goodCSRF},
			status: http.StatusCreated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e, _ := newSessionEnv(t, fakeSessions{})
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			rec := e.do(t, tt.method, tt.path, hostA, body, tt.hdr...)
			if tt.code != "" {
				decodeProblem(t, rec, tt.status, tt.code)
				return
			}
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tt.status, rec.Body)
			}
			if strings.Contains(rec.Body.String(), "ds_secret") {
				t.Errorf("response leaks the session record id: %s", rec.Body)
			}
		})
	}
}

func TestDepositSessionCurrentBodyAndEndCookie(t *testing.T) {
	t.Parallel()
	e, dep := newSessionEnv(t, fakeSessions{})
	cookie := middleware.DepositCookie + "=" + goodToken
	rec := e.do(t, http.MethodGet, "/api/v1/deposit-sessions/current", hostA, nil, "Cookie", cookie)
	var got gen.DepositSession
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Email != "alice@entity-a.example.com" || got.CsrfToken != goodCSRF || !got.CanInvite || got.Kind != gen.DepositorKind("internal") {
		t.Errorf("session body = %+v", got)
	}
	rec = e.do(t, http.MethodDelete, "/api/v1/deposit-sessions/current", hostA, nil, "Cookie", cookie, middleware.HeaderCSRFToken, goodCSRF)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("end: %d %s", rec.Code, rec.Body)
	}
	if sc := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(sc, middleware.DepositCookie+"=;") || !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want the cookie cleared", sc)
	}
	if !slices.Equal(dep.ended, []string{goodToken}) {
		t.Errorf("ended = %v", dep.ended)
	}
}

// TestStartSetsTwoCookies checks, through the real strict handler, that a
// 201 carries the session and recognition cookies as two Set-Cookie
// headers, and that the recognition cookie is read from the request.
func TestStartSetsTwoCookies(t *testing.T) {
	t.Parallel()
	e, _ := newSessionEnv(t, fakeSessions{})
	body := `{"email":"alice@entity-a.example.com"}`
	rec := e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, strings.NewReader(body),
		"Content-Type", "application/json", "Cookie", deposit.RecognitionCookie+"=mac_alice")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 2 || !strings.HasPrefix(cookies[0], middleware.DepositCookie+"="+goodToken+";") ||
		cookies[1] != deposit.RecognitionCookie+"=mac_alice.mac_other; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict" {
		t.Errorf("Set-Cookie = %q", cookies)
	}
	assertSecurityHeaders(t, rec)
	// Without the cookie: a challenge, and no cookie set.
	rec = e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, strings.NewReader(body), "Content-Type", "application/json")
	if rec.Code != http.StatusAccepted || rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("without recognition: %d, Set-Cookie %q", rec.Code, rec.Header().Get("Set-Cookie"))
	}
}

func TestDepositSessionResolverFailure(t *testing.T) {
	t.Parallel()
	e, _ := newSessionEnv(t, fakeSessions{err: errors.New("database is locked")})
	rec := e.do(t, http.MethodGet, "/api/v1/deposit-sessions/current", hostA, nil, "Cookie", middleware.DepositCookie+"="+goodToken)
	decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
	if !strings.Contains(e.appLog.String(), "database is locked") {
		t.Errorf("failure not logged: %s", e.appLog.String())
	}
}

func TestNoSessionsWithoutDepositService(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	rec := e.do(t, http.MethodGet, "/api/v1/deposit-sessions/current", hostA, nil, "Cookie", middleware.DepositCookie+"="+goodToken)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
	if (noSessions{}).CheckCSRF(goodToken, goodCSRF) {
		t.Error("noSessions accepted a CSRF token")
	}
}

func TestSessionResolverWithoutTenant(t *testing.T) {
	t.Parallel()
	_, ok, err := sessionResolver{svc: fakeSessions{}}.ResolveSession(context.Background(), goodToken)
	if ok || err != nil {
		t.Errorf("ResolveSession without tenant = %v, %v, want false, nil", ok, err)
	}
}

// --- Route policies versus the OpenAPI security requirements -------------

// specOperation is the part of an OpenAPI operation the test reads.
type specOperation struct {
	OperationID string                 `yaml:"operationId"`
	Security    *[]map[string][]string `yaml:"security"`
}

func TestRoutePoliciesMatchSpecSecurity(t *testing.T) {
	t.Parallel()
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPISpec, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for path, item := range doc.Paths {
		for verb, node := range item {
			method := strings.ToUpper(verb)
			if !slices.Contains([]string{"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}, method) {
				continue
			}
			var op specOperation
			if err := node.Decode(&op); err != nil {
				t.Fatal(err)
			}
			session, csrf, token, ok := depositSecurity(op.Security)
			me, meCSRF := myTransfersSecurity(op.Security)
			pattern := method + " " + APIBaseURL + path
			p, declared := routePolicies[pattern]
			seen[pattern] = true
			switch {
			case !ok:
				t.Errorf("%s (%s): security alternatives %v are not supported", pattern, op.OperationID, *op.Security)
			case me:
				if !declared || !p.meSession || p.meCSRF != meCSRF || p.depositSession || p.csrf || p.apiToken {
					t.Errorf("%s (%s): route policy %+v, want meSession and meCSRF=%v only", pattern, op.OperationID, p, meCSRF)
				}
			case !session:
				if declared && (p.depositSession || p.csrf || p.apiToken || p.meSession || p.meCSRF) {
					t.Errorf("%s (%s): route policy requires a session or a token, the spec does not", pattern, op.OperationID)
				}
			case !declared || !p.depositSession || p.csrf != csrf || p.apiToken != token || p.meSession || p.meCSRF:
				t.Errorf("%s (%s): route policy %+v, want depositSession, csrf=%v and apiToken=%v", pattern, op.OperationID, p, csrf, token)
			}
		}
	}
	for pattern := range routePolicies {
		if !seen[pattern] {
			t.Errorf("route policy %q matches no operation of the spec", pattern)
		}
	}
}

// myTransfersSecurity reads the "my transfers" security requirements of an
// operation: me is set when myTransfersSession is required, csrf when
// csrfToken goes with it. depositSecurity refuses no combination holding
// myTransfersSession, which is never an alternative of the deposit
// session (checked by the policy test).
func myTransfersSecurity(security *[]map[string][]string) (me, csrf bool) {
	if security == nil {
		return false, false
	}
	for _, alt := range *security {
		if _, ok := alt["myTransfersSession"]; ok {
			_, c := alt["csrfToken"]
			return true, c
		}
	}
	return false, false
}

// depositSecurity reads the security requirements of a public operation:
// session is set when depositSession is required (with csrfToken when
// csrf), token when apiToken is its alternative. ok is false for any
// combination the route policies cannot express: the deposit session must
// be an alternative of its own (with or without csrfToken), apiToken an
// alternative of its own and only beside the deposit session. The
// alternatives without either (admin session, none) are not read.
func depositSecurity(security *[]map[string][]string) (session, csrf, token, ok bool) {
	if security == nil {
		return false, false, false, true
	}
	for _, alt := range *security {
		_, s := alt["depositSession"]
		_, c := alt["csrfToken"]
		_, k := alt["apiToken"]
		switch {
		case s && len(alt) == 1:
			session = true
		case s && c && len(alt) == 2:
			session, csrf = true, true
		case k && len(alt) == 1:
			token = true
		case s || k:
			return false, false, false, false
		}
	}
	return session, csrf, token, !token || session
}

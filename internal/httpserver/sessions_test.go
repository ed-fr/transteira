package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/api/stubs"
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

// pendingSessionOperations are the cookie-authenticated operations still
// answered by stubs: their route policy is added with their implementation.
var pendingSessionOperations = map[string]bool{
	"createTransfer": true, "getTransfer": true, "cancelTransfer": true, "finalizeTransfer": true,
	"getUploadOffset": true, "appendUploadChunk": true, "terminateUpload": true,
}

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
			var session, csrf, only bool
			if op.Security != nil {
				only = len(*op.Security) > 0
				for _, alt := range *op.Security {
					_, s := alt["depositSession"]
					_, c := alt["csrfToken"]
					session, csrf = session || s, csrf || c
					only = only && s
				}
			}
			pattern := method + " " + APIBaseURL + path
			p, declared := routePolicies[pattern]
			seen[pattern] = true
			switch {
			case !session:
				if declared && (p.depositSession || p.csrf) {
					t.Errorf("%s (%s): route policy requires a deposit session, the spec does not", pattern, op.OperationID)
				}
			case pendingSessionOperations[op.OperationID]:
				if !isStubOperation(t, op.OperationID) {
					t.Errorf("%s is implemented: declare its route policy and remove it from pendingSessionOperations", op.OperationID)
				}
			case !only:
				t.Errorf("%s (%s): deposit session as one of several alternatives is not supported yet", pattern, op.OperationID)
			case !declared || !p.depositSession || p.csrf != csrf:
				t.Errorf("%s (%s): route policy %+v, want depositSession and csrf=%v", pattern, op.OperationID, p, csrf)
			}
		}
	}
	for pattern := range routePolicies {
		if !seen[pattern] {
			t.Errorf("route policy %q matches no operation of the spec", pattern)
		}
	}
}

// isStubOperation reports whether the default server answers the operation
// exactly like stubs.Unimplemented, for a zero request.
func isStubOperation(t *testing.T, operationID string) bool {
	t.Helper()
	name := strings.ToUpper(operationID[:1]) + operationID[1:]
	call := func(recv any) []any {
		m := reflect.ValueOf(recv).MethodByName(name)
		if !m.IsValid() {
			t.Fatalf("no method %s", name)
		}
		out := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.Zero(m.Type().In(1))})
		return []any{out[0].Interface(), out[1].Interface()}
	}
	return reflect.DeepEqual(call(public.NewServer()), call(stubs.Unimplemented{}))
}

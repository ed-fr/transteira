package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The express secrets (since API 2.3) through the whole chain: the route
// policies (optional API token, cross-site refusal without it, JSON body,
// body limit), the maintenance mode and the raw body handed to the
// handler.

// expressSecrets is the secret service of the express tests: it records
// the express calls and answers the configured error. The other
// operations are not used (a call panics on the nil interface).
type expressSecrets struct {
	public.SecretService

	mu      sync.Mutex
	err     error
	calls   int
	creator secret.ExpressCreator
	req     secret.ExpressCreateRequest
	ip      netip.Addr
	token   string
	report  secret.AbuseReportRequest
}

func (f *expressSecrets) CreateExpress(_ context.Context, _ *tenant.Tenant, creator secret.ExpressCreator, req secret.ExpressCreateRequest) (secret.Created, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.creator, f.req = creator, req
	return secret.Created{ID: "sec_1", Token: "tts_t", State: store.SecretActive}, f.err
}

func (f *expressSecrets) ReportAbuse(_ context.Context, _ *tenant.Tenant, ip netip.Addr, token string, req secret.AbuseReportRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.ip, f.token, f.report = ip, token, req
	return f.err
}

func (f *expressSecrets) Status(_ context.Context, _ *tenant.Tenant, _ netip.Addr, token string) (secret.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.token = token
	return secret.Status{Express: true, Anonymous: true}, f.err
}

// snapshot returns the recorded calls.
func (f *expressSecrets) snapshot() (int, secret.ExpressCreator, secret.ExpressCreateRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.creator, f.req
}

// expressEnv returns an env serving the express operations with f, the API
// tokens of fakeTokens (one express token, one without the opt-in) and a
// deposit session resolver that fails, so that any session lookup shows.
func expressEnv(t *testing.T, f *expressSecrets) (e *env, express, plain string) {
	t.Helper()
	express, plain = newSecret(t), newSecret(t)
	all := netip.MustParsePrefix("0.0.0.0/0")
	e = newEnv(t, envConfig{
		api: public.NewServer(public.WithSecrets(f)),
		tokens: fakeTokens{secrets: map[string]fakeToken{
			express: {id: "tok_express", allowed: all, express: true},
			plain:   {id: "tok_plain", allowed: netip.MustParsePrefix("198.51.100.0/24")},
		}},
		sessions: fakeSessions{err: errors.New("the session store was consulted")},
		trusted:  func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.10") },
	})
	return e, express, plain
}

// expressCreateBody is a well-formed creation body.
const expressCreateBody = `{"encryptedText":"AQvm","verifier":"v","keyVerifier":"k","expiresIn":"1h","passphrase":{}}`

func TestExpressCreationRoute(t *testing.T) {
	t.Parallel()
	f := &expressSecrets{}
	e, express, plain := expressEnv(t, f)
	const path = "/api/v1/express-secrets"
	jsonCT := []string{"Content-Type", "application/json"}

	// Anonymous, same origin, with a deposit session cookie (ignored): the
	// handler gets the raw body, the client IP of the trusted proxy and
	// no token.
	rec := e.do(t, http.MethodPost, path, hostA, strings.NewReader(expressCreateBody), append(jsonCT,
		"Origin", "https://"+hostA, "Sec-Fetch-Site", "same-origin", "X-Forwarded-For", "203.0.113.9",
		"Cookie", middleware.DepositCookie+"="+goodToken)...)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(rec.Body.String(), `"token":"tts_t"`) {
		t.Fatalf("anonymous creation: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	_, creator, req := f.snapshot()
	if creator.APITokenID != "" || creator.ClientIP != netip.MustParseAddr("203.0.113.9") ||
		req.EncryptedText != "AQvm" || req.ExpiresIn != "1h" || len(req.Extra) != 1 || req.Extra[0] != "/passphrase" {
		t.Errorf("anonymous call: %+v %+v", creator, req)
	}

	// A malformed body reaches the service (its switches come first).
	f.err = secret.ErrExpressDisabled
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(`{`), jsonCT...)
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeExpressSecretsDisabled)
	f.err = nil

	// Cross-site without token: refused before the service.
	before, _, _ := f.snapshot()
	for _, h := range [][]string{
		{"Origin", "https://evil.example.net"},
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "same-site"},
	} {
		rec := e.do(t, http.MethodPost, path, hostA, strings.NewReader(expressCreateBody), append(jsonCT, h...)...)
		decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	}
	// Not JSON: 415; too large: 413.
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(expressCreateBody), "Content-Type", "text/plain")
	decodeProblem(t, rec, http.StatusUnsupportedMediaType, problem.CodeUnsupportedMediaType)
	big := `{"encryptedText":"` + strings.Repeat("A", int(ExpressBodyLimit)) + `"}`
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(big), jsonCT...)
	decodeProblem(t, rec, http.StatusRequestEntityTooLarge, problem.CodePayloadTooLarge)
	if after, _, _ := f.snapshot(); after != before {
		t.Errorf("the service was called %d times by refused requests", after-before)
	}

	// With a valid token, from another site too: the token and its opt-in
	// reach the handler, the session cookie is dropped.
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(expressCreateBody), append(jsonCT,
		"Authorization", "Bearer "+express, "Origin", "https://tickets.example.net", "Sec-Fetch-Site", "cross-site",
		"Cookie", middleware.DepositCookie+"="+goodToken, "X-Forwarded-For", "203.0.113.9")...)
	if rec.Code != http.StatusCreated {
		t.Fatalf("token creation: %d %s", rec.Code, rec.Body.String())
	}
	if _, creator, _ := f.snapshot(); creator.APITokenID != "tok_express" || !creator.ExpressAllowed {
		t.Errorf("token creator = %+v", creator)
	}
	// A token without the opt-in is passed as such (the service refuses).
	f.err = secret.ErrExpressTokenNotAllowed
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(expressCreateBody), append(jsonCT,
		"Authorization", "Bearer "+plain, "X-Forwarded-For", "198.51.100.4")...)
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeExpressTokenNotAllowed)
	if _, creator, _ := f.snapshot(); creator.APITokenID != "tok_plain" || creator.ExpressAllowed {
		t.Errorf("token without opt-in = %+v", creator)
	}
	f.err = nil

	// An invalid token is never downgraded to an anonymous creation, and a
	// valid one outside its ranges is refused.
	before, _, _ = f.snapshot()
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(expressCreateBody), append(jsonCT,
		"Authorization", "Bearer "+newSecret(t))...)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeInvalidCredentials)
	if rec.Header().Get("WWW-Authenticate") == "" || !strings.Contains(e.secLog.String(), "api_token_invalid") {
		t.Errorf("invalid token: %v, security log %s", rec.Header(), e.secLog.String())
	}
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(expressCreateBody), append(jsonCT,
		"Authorization", "Bearer "+plain, "X-Forwarded-For", "203.0.113.9")...)
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeIPNotAllowed)
	if after, _, _ := f.snapshot(); after != before {
		t.Errorf("the service was called %d times by refused tokens", after-before)
	}
	if strings.Contains(e.appLog.String(), "the session store was consulted") {
		t.Errorf("a deposit session was looked up: %s", e.appLog.String())
	}
}

// The maintenance mode refuses the creation, with or without token, and
// leaves the reading and the reports open.
func TestExpressMaintenance(t *testing.T) {
	t.Parallel()
	f := &expressSecrets{}
	e, express, _ := expressEnv(t, f)
	e.maintenance.Store(true)
	jsonCT := []string{"Content-Type", "application/json"}
	for _, h := range [][]string{jsonCT, append(jsonCT, "Authorization", "Bearer "+express)} {
		rec := e.do(t, http.MethodPost, "/api/v1/express-secrets", hostA, strings.NewReader(expressCreateBody), h...)
		p := decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeMaintenance)
		if p.RetryAfterSeconds == nil {
			t.Error("maintenance without Retry-After")
		}
	}
	if n, _, _ := f.snapshot(); n != 0 {
		t.Errorf("%d calls in maintenance", n)
	}
	token := "tts_" + strings.Repeat("A", 43)
	rec := e.do(t, http.MethodGet, "/api/v1/secret-links/"+token, hostA, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"express":true`) {
		t.Errorf("status in maintenance: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, http.MethodPost, "/api/v1/secret-links/"+token+"/abuse-reports", hostA,
		strings.NewReader(`{"category":"phishing"}`), jsonCT...)
	if rec.Code != http.StatusAccepted {
		t.Errorf("report in maintenance: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSecretAbuseReportRoute(t *testing.T) {
	t.Parallel()
	f := &expressSecrets{}
	e, express, _ := expressEnv(t, f)
	token := "tts_" + strings.Repeat("B", 43)
	path := "/api/v1/secret-links/" + token + "/abuse-reports"
	body := `{"category":"phishing","message":"Fake bank."}`
	rec := e.do(t, http.MethodPost, path, hostA, strings.NewReader(body),
		"Content-Type", "application/json", "Origin", "https://"+hostA, "X-Forwarded-For", "203.0.113.9")
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("report: %d %s", rec.Code, rec.Body.String())
	}
	if f.token != token || f.ip != netip.MustParseAddr("203.0.113.9") || f.report.Category != "phishing" || f.report.Message != "Fake bank." {
		t.Errorf("report call = %+v", f)
	}
	if got := rec.Header().Get("X-Robots-Tag"); got != UIRobots {
		t.Errorf("X-Robots-Tag %q", got)
	}
	before, _, _ := f.snapshot()
	for _, h := range [][]string{
		{"Content-Type", "application/json", "Origin", "https://evil.example.net"},
		{"Content-Type", "application/json", "Sec-Fetch-Site", "cross-site"},
		// A token is not a credential of this operation: no way around
		// the cross-site check.
		{"Content-Type", "application/json", "Sec-Fetch-Site", "cross-site", "Authorization", "Bearer " + express},
	} {
		rec := e.do(t, http.MethodPost, path, hostA, strings.NewReader(body), h...)
		decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	}
	rec = e.do(t, http.MethodPost, path, hostA, strings.NewReader(body), "Content-Type", "application/x-www-form-urlencoded")
	decodeProblem(t, rec, http.StatusUnsupportedMediaType, problem.CodeUnsupportedMediaType)
	if after, _, _ := f.snapshot(); after != before {
		t.Errorf("the service was called %d times by refused reports", after-before)
	}
}

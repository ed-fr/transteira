package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/provisioning"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/tenant"
)

// provisioningSecrets are the provisioning tokens known to
// fakeProvisioningTokens, fresh for each test (never literals).
type provisioningSecrets struct {
	good, revoked, expired, narrow, boom string
}

const provisioningTokenID = "prv_01JAAAAAAAAAAAAAAAAAAAAAAA"

// newProvisioningSecret returns a fresh provisioning token secret.
func newProvisioningSecret(t *testing.T) string {
	t.Helper()
	g, err := provisioning.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return g.Secret
}

func newProvisioningSecrets(t *testing.T) provisioningSecrets {
	t.Helper()
	return provisioningSecrets{
		good: newProvisioningSecret(t), revoked: newProvisioningSecret(t), expired: newProvisioningSecret(t),
		narrow: newProvisioningSecret(t), boom: newProvisioningSecret(t),
	}
}

// fakeProvisioningTokens authenticates like provisioning.Service: good
// from 192.0.2.0/24, revoked, expired, narrow (outside its ranges), boom
// (a store failure); any other secret is malformed or unknown.
type fakeProvisioningTokens struct{ s provisioningSecrets }

func (f fakeProvisioningTokens) Authenticate(_ context.Context, raw string, ip netip.Addr) (provisioning.Principal, error) {
	switch {
	case raw == f.s.boom:
		return provisioning.Principal{}, errors.New("database is locked")
	case !provisioning.ValidSecret(raw):
		return provisioning.Principal{}, &provisioning.AuthError{Reason: provisioning.ReasonMalformed}
	case raw == f.s.revoked:
		return provisioning.Principal{}, &provisioning.AuthError{Reason: provisioning.ReasonRevoked, TokenID: provisioningTokenID}
	case raw == f.s.expired:
		return provisioning.Principal{}, &provisioning.AuthError{Reason: provisioning.ReasonExpired, TokenID: provisioningTokenID}
	case raw == f.s.narrow:
		return provisioning.Principal{}, &provisioning.AuthError{Reason: provisioning.ReasonIPNotAllowed, TokenID: provisioningTokenID}
	case raw != f.s.good:
		return provisioning.Principal{}, &provisioning.AuthError{Reason: provisioning.ReasonUnknown}
	case !netip.MustParsePrefix("192.0.2.0/24").Contains(ip):
		return provisioning.Principal{}, &provisioning.AuthError{Reason: provisioning.ReasonIPNotAllowed, TokenID: provisioningTokenID}
	}
	return provisioning.Principal{TokenID: provisioningTokenID, Name: "msp", Prefix: raw[:provisioning.PrefixLen]}, nil
}

// fakeProvisioningService answers the provisioning API with the tenant
// list of the principal of the request: one tenant named after its token.
// Any other method panics (nil embedded interface).
type fakeProvisioningService struct {
	admin.ProvisioningService
}

func (fakeProvisioningService) ListTenants(_ context.Context, p provisioning.Principal) ([]provisioning.Tenant, error) {
	return []provisioning.Tenant{{
		ID: "ten_01JAB00000000000000ENT1TYC", Name: p.TokenID, FQDN: "entity-c.transfer.example.com",
		SetupState: tenant.SetupStateSetup, CreatedAt: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
	}}, nil
}

// newProvisioningEnv returns an env whose admin host serves the
// provisioning API over fakeProvisioningService, authenticated through the
// real adapter over fakeProvisioningTokens.
func newProvisioningEnv(t *testing.T, s provisioningSecrets, opts ...Option) *env {
	t.Helper()
	return newEnv(t, envConfig{
		adminSessions: fakeAdminSessions{},
		adminAPI: admin.NewServer(admin.WithService(&fakeAdminService{}), admin.WithTenants(fakeTenantList{}),
			admin.WithProvisioningService(fakeProvisioningService{})),
		provisioning: NewProvisioningAuthenticator(fakeProvisioningTokens{s: s}),
		opts:         opts,
	})
}

const provisionedTenantsTarget = APIBaseURL + "/provisioning/tenants"

// TestProvisioningAuthenticator checks that the adapter plugs in: an
// accepted token reaches the handler with its principal, whatever admin
// session cookie the request also carries (a failing one included: it is
// never read), and the scheme is case-insensitive.
func TestProvisioningAuthenticator(t *testing.T) {
	t.Parallel()
	s := newProvisioningSecrets(t)
	e := newProvisioningEnv(t, s)
	for _, hdr := range [][]string{
		{"Authorization", "Bearer " + s.good},
		{"Authorization", "bearer " + s.good, "Cookie", middleware.AdminCookie + "=" + adminBoomToken},
		{
			"Authorization", "Bearer " + s.good, "Cookie", middleware.AdminCookie + "=" + adminGoodToken,
			"Origin", "https://evil.example.net", "Sec-Fetch-Site", "cross-site",
		},
	} {
		rec := e.do(t, http.MethodGet, provisionedTenantsTarget, hostAdmin, nil, hdr...)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"`+provisioningTokenID+`"`) {
			t.Fatalf("%v: %d %s", hdr, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Set-Cookie") != "" {
			t.Errorf("%v: Set-Cookie %q", hdr, rec.Header().Get("Set-Cookie"))
		}
	}
	// The admin operations are not affected by the provisioning check.
	rec := e.do(t, http.MethodGet, APIBaseURL+"/admin/setup", hostAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("admin setup status %d", rec.Code)
	}
	if e.secLog.String() != "" {
		t.Errorf("security log:\n%s", e.secLog.String())
	}
}

// refusalShape is what a client sees of an answer: its status, headers
// and body, but the request identifier.
func refusalShape(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	delete(body, "instance")
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	h := rec.Header().Clone()
	h.Del("X-Request-Id")
	hb, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(rec.Code) + " " + string(hb) + " " + string(b)
}

// TestProvisioningRefusals checks that every refusal reason gives the same
// answer (no oracle, T-268), with a provisioning_token_invalid line of the
// real client IP and the tenant "-", never the token, and its reason in
// the application log only. A store failure gets the same answer, without
// security event.
func TestProvisioningRefusals(t *testing.T) {
	t.Parallel()
	s := newProvisioningSecrets(t)
	failures := ratelimit.NewWindow(100, time.Hour, ratelimit.WithLockout(time.Hour))
	e := newProvisioningEnv(t, s, WithProvisioningFailures(failures))
	apiToken := newSecret(t) // a tenant API token, tt_...
	refusals := []struct {
		name   string
		hdr    []string
		reason string
	}{
		{"unknown", []string{"Authorization", "Bearer " + newProvisioningSecret(t)}, provisioning.ReasonUnknown},
		{"malformed", []string{"Authorization", "Bearer ttp_short"}, provisioning.ReasonMalformed},
		{"tenant api token", []string{"Authorization", "Bearer " + apiToken}, provisioning.ReasonMalformed},
		{"revoked", []string{"Authorization", "Bearer " + s.revoked}, provisioning.ReasonRevoked},
		{"expired", []string{"Authorization", "Bearer " + s.expired}, provisioning.ReasonExpired},
		{"outside the ranges", []string{"Authorization", "Bearer " + s.narrow}, provisioning.ReasonIPNotAllowed},
		{"empty", []string{"Authorization", "Bearer "}, reasonMalformedHeader},
		{"no token", []string{"Authorization", "Bearer"}, reasonMalformedHeader},
		{"other scheme", []string{"Authorization", "Basic dXNlcjpwYXNz"}, reasonMalformedHeader},
	}
	var want string
	for _, r := range refusals {
		hdr := append([]string{"Cookie", middleware.AdminCookie + "=" + adminGoodToken}, r.hdr...)
		rec := e.do(t, http.MethodGet, provisionedTenantsTarget, hostAdmin, nil, hdr...)
		decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeProvisioningTokenInvalid)
		got := refusalShape(t, rec)
		if want == "" {
			want = got
		} else if got != want {
			t.Errorf("%s: answer\n%s\nwant\n%s", r.name, got, want)
		}
		if !strings.Contains(e.appLog.String(), `"reason":"`+r.reason+`"`) {
			t.Errorf("%s: reason %q not in the application log", r.name, r.reason)
		}
	}
	if !strings.Contains(want, `"Www-Authenticate":["Bearer error=\"invalid_token\""]`) {
		t.Errorf("answer %s", want)
	}
	// Several Authorization headers: ambiguous, refused alike.
	req := httptest.NewRequest(http.MethodGet, provisionedTenantsTarget, nil)
	req.Host, req.RemoteAddr = hostAdmin, "192.0.2.10:4242"
	req.Header.Add("Authorization", "Bearer "+s.good)
	req.Header.Add("Authorization", "Bearer "+s.good)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if got := refusalShape(t, rec); got != want {
		t.Errorf("several headers: answer\n%s\nwant\n%s", got, want)
	}
	// A store failure: the same answer, logged at error level, neither a
	// security event nor a failure of the client.
	rec = e.do(t, http.MethodGet, provisionedTenantsTarget, hostAdmin, nil, "Authorization", "Bearer "+s.boom)
	if got := refusalShape(t, rec); got != want {
		t.Errorf("store failure: answer\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(e.appLog.String(), "database is locked") {
		t.Errorf("store failure not logged: %s", e.appLog.String())
	}

	sec := e.secLog.String()
	wantLines := len(refusals) + 1
	if n := strings.Count(sec, "ip=192.0.2.10 tenant=- event=provisioning_token_invalid\n"); n != wantLines {
		t.Errorf("%d provisioning_token_invalid lines, want %d:\n%s", n, wantLines, sec)
	}
	if n := strings.Count(sec, "\n"); n != wantLines {
		t.Errorf("%d security log lines, want %d:\n%s", n, wantLines, sec)
	}
	if locked, _ := failures.Locked(middleware.RateLimitKey(netip.MustParseAddr("192.0.2.10"))); locked {
		t.Error("locked out below the limit")
	}
	for _, secret := range []string{s.good, s.revoked, s.expired, s.narrow, s.boom, apiToken} {
		if strings.Contains(sec, secret) || strings.Contains(e.appLog.String(), secret) {
			t.Error("a token secret was logged")
		}
	}
	if !strings.Contains(e.appLog.String(), provisioningTokenID) {
		t.Errorf("refused token not identified in the application log: %s", e.appLog.String())
	}
}

// TestProvisioningLockout checks the per-IP lockout with the default
// settings: the 11th invalid token from one client gets 429 (one
// throttled rate_limited event, no new failure), and a valid token of the
// locked-out IP still passes without lifting nor extending the lockout.
func TestProvisioningLockout(t *testing.T) {
	t.Parallel()
	s := newProvisioningSecrets(t)
	failures := newTokenFailures()
	e := newProvisioningEnv(t, s, WithProvisioningFailures(failures))
	for range APITokenFailureLimit {
		rec := e.do(t, http.MethodGet, provisionedTenantsTarget, hostAdmin, nil, "Authorization", "Bearer "+newProvisioningSecret(t))
		decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeProvisioningTokenInvalid)
	}
	for range 3 {
		rec := e.do(t, http.MethodGet, provisionedTenantsTarget, hostAdmin, nil, "Authorization", "Bearer "+s.revoked)
		p := decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
		if p.RetryAfterSeconds == nil || rec.Header().Get("Retry-After") == "" {
			t.Errorf("429 without retry delay: %+v", p)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "" {
			t.Errorf("429 with WWW-Authenticate %q", got)
		}
	}
	key := middleware.RateLimitKey(netip.MustParseAddr("192.0.2.10"))
	_, before := failures.Locked(key)
	rec := e.do(t, http.MethodGet, provisionedTenantsTarget, hostAdmin, nil, "Authorization", "Bearer "+s.good)
	if rec.Code != http.StatusOK {
		t.Errorf("valid token while locked out: %d %s", rec.Code, rec.Body.String())
	}
	if locked, after := failures.Locked(key); !locked || after > before {
		t.Errorf("lockout after a valid token: %v, %v then %v", locked, before, after)
	}
	// No Authorization header at all is no failure: still 401.
	rec = e.do(t, http.MethodGet, provisionedTenantsTarget, hostAdmin, nil)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
	sec := e.secLog.String()
	if n := strings.Count(sec, `tenant=- event=rate_limited scope="provisioning_token"`); n != 1 {
		t.Errorf("%d rate_limited events, want 1 (throttled):\n%s", n, sec)
	}
	if n := strings.Count(sec, "event=provisioning_token_invalid"); n != APITokenFailureLimit {
		t.Errorf("%d provisioning_token_invalid events, want %d", n, APITokenFailureLimit)
	}
}

// TestProvisioningTokenConfusion checks that a provisioning token is never
// a tenant API token (T-269): ttp_ on a deposit operation of a tenant host
// is an invalid API token, and the provisioning operations do not exist on
// a tenant host.
func TestProvisioningTokenConfusion(t *testing.T) {
	t.Parallel()
	te := newTokenEnv(t, nil)
	secret := newProvisioningSecret(t)
	rec := te.call(t, tokenRoutes[1], "Authorization", "Bearer "+secret)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeInvalidCredentials)
	rec = te.do(t, http.MethodGet, provisionedTenantsTarget, hostA, nil, "Authorization", "Bearer "+secret)
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	if strings.Contains(te.secLog.String(), "provisioning_token_invalid") {
		t.Errorf("security log:\n%s", te.secLog.String())
	}
}

// failingProvisioning fails every authentication with err.
type failingProvisioning struct{ err error }

func (f failingProvisioning) AuthenticateProvisioning(context.Context, string, netip.Addr) (context.Context, error) {
	return nil, f.err
}

// TestProvisioningFailureLevel checks that a lookup failure is logged at
// Error level, and only at Debug level when the client canceled.
func TestProvisioningFailureLevel(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		cancel bool
		level  string
	}{{"server failure", false, "ERROR"}, {"client canceled", true, "DEBUG"}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf lockedBuffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			err := errors.New("database is locked")
			if tt.cancel {
				err = fmt.Errorf("lookup: %w", context.Canceled)
			}
			a := newProvisioningAuth(failingProvisioning{err}, newTokenFailures(),
				NewSecurityEvents(securitylog.New(&lockedBuffer{}), logger), logger)
			h := a.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler reached") }))
			req := httptest.NewRequest(http.MethodGet, provisionedTenantsTarget, nil)
			req.Pattern = http.MethodGet + " " + provisionedTenantsTarget
			req.Header.Set("Authorization", "Bearer ttp_x")
			ctx := req.Context()
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
			if got := buf.String(); !strings.Contains(got, `"level":"`+tt.level+`"`) || !strings.Contains(got, "provisioning token lookup failed") {
				t.Errorf("log %s, want the failure at level %s", got, tt.level)
			}
		})
	}
}

// TestProvisioningAuthenticatorAdapter checks the adapter itself: the
// principal of an accepted token is in the context, a refusal passes
// through.
func TestProvisioningAuthenticatorAdapter(t *testing.T) {
	t.Parallel()
	s := newProvisioningSecrets(t)
	a := NewProvisioningAuthenticator(fakeProvisioningTokens{s: s})
	ctx, err := a.AuthenticateProvisioning(context.Background(), s.good, netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := provisioning.FromContext(ctx); !ok || p.TokenID != provisioningTokenID {
		t.Errorf("principal %+v %v", p, ok)
	}
	if _, err := a.AuthenticateProvisioning(context.Background(), s.good, netip.MustParseAddr("203.0.113.1")); !errors.Is(err, provisioning.ErrInvalidToken) {
		t.Errorf("outside the ranges: %v", err)
	}
}

// FuzzBearerToken checks that bearerToken accepts exactly one Bearer
// scheme followed by a space and a non-empty trimmed token.
func FuzzBearerToken(f *testing.F) {
	for _, seed := range []string{"", "Bearer", "Bearer ", "Bearer x", "bearer  x ", "Basic x", "Bearer\tx", "BEARER ttp_\x00", "Bearerx y"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		token, ok := bearerToken(header)
		if !ok {
			if token != "" {
				t.Fatalf("refused %q with token %q", header, token)
			}
			return
		}
		if token == "" || token != strings.TrimSpace(token) {
			t.Fatalf("accepted %q with token %q", header, token)
		}
		if len(header) <= len(bearerScheme) || !strings.EqualFold(header[:len(bearerScheme)], bearerScheme) ||
			header[len(bearerScheme)] != ' ' || !strings.Contains(header, token) {
			t.Fatalf("accepted %q", header)
		}
	})
}

package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/apitoken"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/tenant"
)

// API token authentication settings (OpenAPI security scheme apiToken).
//
// The failures are counted per client IP ([middleware.RateLimitKey]: an
// IPv6 client per /64), in memory: APITokenFailureLimit invalid tokens
// within APITokenFailureWindow lock the IP out of the token path for
// APITokenLockout. The values follow the per-IP limit of the admin
// password failures (20 per IP, kept by internal/adminauth), halved
// because a script holding a valid token never fails: a token is a 256-bit
// random secret, so the lockout is a guard against floods and log noise,
// not against guessing. Every failure is also written to the security log
// (api_token_invalid) for fail2ban and CrowdSec, which ban for longer.
//
// A locked-out IP is still authenticated: a valid token passes (and neither
// resets nor extends the lockout), and only the invalid ones get 429. The
// trade-off: a client behind a shared egress (NAT, corporate proxy) cannot
// lock the legitimate scripts of its neighbors out by flooding invalid
// tokens, at the cost of one token lookup (a hash and an indexed read, under
// the global per-IP rate limit) per request of a locked-out IP instead of
// none.
const (
	// ScopeAPIToken is the rate-limit scope of the per-IP lockout after
	// invalid API tokens.
	ScopeAPIToken = "api_token"
	// APITokenFailureLimit is the number of invalid tokens one client IP
	// may present within APITokenFailureWindow before being locked out.
	APITokenFailureLimit = 10
	// APITokenFailureWindow is the sliding window of the failure count.
	APITokenFailureWindow = 10 * time.Minute
	// APITokenLockout is the duration of the lockout: every invalid token
	// of the IP then gets 429, without counting a new failure; a valid
	// token still passes.
	APITokenLockout = 15 * time.Minute
)

// bearerScheme is the authentication scheme of the API tokens (RFC 6750),
// compared case-insensitively.
const bearerScheme = "Bearer"

// WWW-Authenticate challenges of the 401 answers of the token path (RFC 6750
// section 3): without error code when no token was presented, invalid_token
// for a malformed, unknown, revoked or expired one.
const (
	challengeBearer       = bearerScheme
	challengeInvalidToken = bearerScheme + ` error="invalid_token"`
)

// APITokens authenticates the API tokens (*apitoken.Service).
type APITokens interface {
	// Authenticate checks the Authorization header of a request served on
	// the host of tenant tid from clientIP; see apitoken.Service.
	Authenticate(ctx context.Context, tid tenant.ID, header string, clientIP netip.Addr) (apitoken.Principal, error)
}

// noTokens authenticates no token, when Deps.APITokens is nil.
type noTokens struct{}

// Authenticate implements APITokens: every token is invalid.
func (noTokens) Authenticate(context.Context, tenant.ID, string, netip.Addr) (apitoken.Principal, error) {
	return apitoken.Principal{}, apitoken.ErrInvalid
}

// TokenFailures counts the invalid API tokens per key and locks a key out
// (*ratelimit.Window).
type TokenFailures interface {
	// Locked reports whether key is locked out and for how long.
	Locked(key string) (locked bool, retryAfter time.Duration)
	// Fail records one failure of key.
	Fail(key string) (locked bool, retryAfter time.Duration)
}

// newTokenFailures returns the default failure counter.
func newTokenFailures() *ratelimit.Window {
	return ratelimit.NewWindow(APITokenFailureLimit, APITokenFailureWindow, ratelimit.WithLockout(APITokenLockout))
}

// hasBearer reports whether r carries an Authorization header with the
// Bearer scheme (whatever follows it).
func hasBearer(r *http.Request) bool {
	for _, v := range r.Header.Values("Authorization") {
		scheme, _, _ := strings.Cut(v, " ")
		if strings.EqualFold(scheme, bearerScheme) {
			return true
		}
	}
	return false
}

// tokenAuthenticated reports whether the request was authenticated by an
// API token: the deposit session, CSRF and Origin checks then do not
// apply.
func tokenAuthenticated(r *http.Request) bool {
	_, ok := middleware.APITokenFrom(r.Context())
	return ok
}

// tokenAuth is the per-operation middleware of the API token path.
type tokenAuth struct {
	tokens   APITokens
	failures TokenFailures
	events   *SecurityEvents
	// throttle limits the rate_limited events of a locked-out key to one
	// per middleware.SecurityEventInterval.
	throttle *ratelimit.Limiter
	logger   *slog.Logger
}

// newTokenAuth returns the token middleware state.
func newTokenAuth(tokens APITokens, failures TokenFailures, events *SecurityEvents, logger *slog.Logger) *tokenAuth {
	if tokens == nil {
		tokens = noTokens{}
	}
	return &tokenAuth{
		tokens: tokens, failures: failures, events: events, logger: logger,
		throttle: ratelimit.New(rate.Every(middleware.SecurityEventInterval), 1),
	}
}

// middleware authenticates, with the API token, the requests of the
// operations whose policy accepts one (routePolicy.apiToken) and that
// carry an Authorization header with the Bearer scheme. Such a request
// takes the token path only: the principal is stored in the context
// (middleware.APITokenFrom), the Cookie header is dropped so that no
// deposit session can be mixed in, and the deposit session, CSRF and
// Origin checks are skipped. Its failures:
//
//   - an empty, malformed, unknown (on this tenant), revoked or expired
//     token: 401 invalid-credentials with a WWW-Authenticate Bearer
//     challenge, an api_token_invalid event and one failure of the IP;
//   - the same from an IP locked out after too many invalid tokens: 429
//     rate-limited with Retry-After and a rate_limited event (scope
//     api_token, throttled), no new failure nor api_token_invalid event (a
//     valid token of a locked-out IP passes, see APITokenLockout);
//   - a valid token used from outside its allowed ranges: 403
//     ip-not-allowed and a deposit_refused event (reason ip);
//   - a store failure: 500 internal-error, logged at Error level (Debug
//     when the client went away, see middleware.ClientGone).
//
// The token itself is never logged. Any other request passes untouched:
// without a Bearer header, the deposit session path applies.
func (a *tokenAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !policyOf(r).apiToken || !hasBearer(r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		ip := middleware.ClientIP(ctx)
		key := middleware.RateLimitKey(ip)
		t, ok := tenant.FromContext(ctx)
		if !ok {
			a.logger.ErrorContext(ctx, "api token request without tenant",
				slog.String("request_id", middleware.RequestID(ctx)))
			writeProblem(w, r, problem.New(problem.CodeInternalError))
			return
		}
		header := ""
		if values := r.Header.Values("Authorization"); len(values) == 1 {
			header = values[0]
		} // several Authorization headers: ambiguous, refused as invalid
		p, err := a.tokens.Authenticate(ctx, t.ID, header, ip)
		switch {
		case err == nil:
		case errors.Is(err, apitoken.ErrMissing), errors.Is(err, apitoken.ErrInvalid):
			if locked, retry := a.failures.Locked(key); locked {
				a.rateLimited(ctx, ip, t.FQDN, key)
				writeProblem(w, r, problem.New(problem.CodeRateLimited, problem.WithRetryAfter(retry)))
				return
			}
			a.events.APITokenInvalid(ctx, ip, t.FQDN)
			a.failures.Fail(key)
			challenge := challengeInvalidToken
			if errors.Is(err, apitoken.ErrMissing) {
				challenge = challengeBearer
			}
			w.Header().Set("WWW-Authenticate", challenge)
			writeProblem(w, r, problem.New(problem.CodeInvalidCredentials))
			return
		case errors.Is(err, apitoken.ErrIPNotAllowed):
			a.events.DepositRefused(ctx, ip, t.FQDN, securitylog.ReasonIP)
			a.logger.InfoContext(ctx, "api token used from a client ip outside its allowed ranges",
				slog.String("request_id", middleware.RequestID(ctx)),
				slog.String("tenant", string(t.ID)), slog.String("token", p.TokenID))
			writeProblem(w, r, problem.New(problem.CodeIPNotAllowed))
			return
		default:
			level := slog.LevelError
			if middleware.ClientGone(ctx, err) {
				level = slog.LevelDebug // the client went away
			}
			a.logger.Log(ctx, level, "api token lookup failed",
				slog.String("request_id", middleware.RequestID(ctx)),
				slog.String("error", err.Error()))
			writeProblem(w, r, problem.New(problem.CodeInternalError))
			return
		}
		r = r.WithContext(middleware.WithAPIToken(ctx, middleware.TokenPrincipal{TokenID: p.TokenID, Name: p.Name}))
		r.Header = r.Header.Clone()
		r.Header.Del("Cookie")
		next.ServeHTTP(w, r)
	})
}

// rateLimited records a rate_limited event of scope ScopeAPIToken for a
// locked-out key, at most once per middleware.SecurityEventInterval.
func (a *tokenAuth) rateLimited(ctx context.Context, ip netip.Addr, fqdn, key string) {
	if ok, _ := a.throttle.Allow(key); ok {
		a.events.RateLimited(ctx, ip, fqdn, ScopeAPIToken)
	}
}

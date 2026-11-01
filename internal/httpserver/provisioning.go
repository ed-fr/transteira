package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/provisioning"
	"github.com/ed-fr/transteira/internal/ratelimit"
)

// ScopeProvisioningToken is the rate-limit scope of the per-IP lockout
// after invalid provisioning tokens. The lockout uses the settings of the
// API tokens (APITokenFailureLimit invalid tokens within
// APITokenFailureWindow lock the IP out for APITokenLockout), with a
// counter of its own.
const ScopeProvisioningToken = "provisioning_token"

// ProvisioningAuthenticator authenticates the provisioning tokens of the
// provisioning operations (OpenAPI security scheme provisioningToken,
// since API 1.2). It is the only credential of those operations: session
// cookies and CSRF tokens are never read there.
type ProvisioningAuthenticator interface {
	// AuthenticateProvisioning checks rawToken (the value after "Bearer ")
	// presented from client and returns ctx carrying the provisioning
	// principal the handlers read. An error matching
	// provisioning.ErrInvalidToken refuses the token (an unknown, revoked or
	// expired token, a client outside the allowed ranges of the token); any
	// other error is a failure of the authenticator. Both are answered
	// alike (401 provisioning-token-invalid).
	AuthenticateProvisioning(ctx context.Context, rawToken string, client netip.Addr) (context.Context, error)
}

// ProvisioningTokens authenticates the provisioning tokens
// (*provisioning.Service).
type ProvisioningTokens interface {
	Authenticate(ctx context.Context, raw string, clientIP netip.Addr) (provisioning.Principal, error)
}

// NewProvisioningAuthenticator returns the ProvisioningAuthenticator of
// tokens: the principal of an accepted token is put in the context
// (provisioning.NewContext), where the provisioning handlers read it.
func NewProvisioningAuthenticator(tokens ProvisioningTokens) ProvisioningAuthenticator {
	return provisioningAuthenticator{tokens: tokens}
}

// provisioningAuthenticator adapts ProvisioningTokens.
type provisioningAuthenticator struct{ tokens ProvisioningTokens }

// AuthenticateProvisioning implements ProvisioningAuthenticator.
func (a provisioningAuthenticator) AuthenticateProvisioning(ctx context.Context, raw string, client netip.Addr) (context.Context, error) {
	p, err := a.tokens.Authenticate(ctx, raw, client)
	if err != nil {
		return nil, err
	}
	return provisioning.NewContext(ctx, p), nil
}

// Internal reasons of a refusal decided by the middleware itself, for the
// application log only.
const (
	// reasonMalformedHeader: an Authorization header that is not one
	// non-empty Bearer credential.
	reasonMalformedHeader = "malformed_header"
	// reasonNoService: no provisioning service (fail closed).
	reasonNoService = "no_service"
)

// provisioningAuth is the per-operation middleware of the provisioning
// operations.
type provisioningAuth struct {
	auth     ProvisioningAuthenticator
	failures TokenFailures
	events   *SecurityEvents
	// throttle limits the rate_limited events of a locked-out key to one
	// per middleware.SecurityEventInterval.
	throttle *ratelimit.Limiter
	logger   *slog.Logger
}

// newProvisioningAuth returns the provisioning middleware state; a nil
// auth accepts no token (fail closed).
func newProvisioningAuth(auth ProvisioningAuthenticator, failures TokenFailures, events *SecurityEvents, logger *slog.Logger) *provisioningAuth {
	return &provisioningAuth{
		auth: auth, failures: failures, events: events, logger: logger,
		throttle: ratelimit.New(rate.Every(middleware.SecurityEventInterval), 1),
	}
}

// middleware refuses every provisioning operation (route patterns under
// ProvisioningPrefix) that does not carry a provisioning token accepted by
// the authenticator, before any session, CSRF, body or handler. Other
// routes pass through untouched. Its answers:
//
//   - no Authorization header: 401 unauthenticated with a WWW-Authenticate
//     Bearer challenge; nothing is logged nor counted;
//   - any other refusal (an Authorization header that is not exactly one
//     non-empty Bearer credential, a malformed, unknown, revoked or expired
//     token, a client outside the ranges of the token, no provisioning
//     service, or a failure of the authenticator): the same 401
//     provisioning-token-invalid with the invalid_token challenge, whatever
//     the reason (no oracle, T-268). Each refusal but a failure of the
//     authenticator writes a provisioning_token_invalid event (tenant "-",
//     real client IP, never the token) and counts one failure of the IP;
//     its internal reason goes to the application log only;
//   - the same from an IP locked out after too many invalid tokens: 429
//     rate-limited with Retry-After and a rate_limited event (scope
//     provisioning_token, throttled), no new failure nor event. A valid
//     token of a locked-out IP passes, as on the API token path.
//
// An accepted request reaches the handlers with the principal in its
// context and without its Cookie header, so that no session can ever be
// mixed in.
func (a *provisioningAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isProvisioningPattern(r.Pattern) {
			next.ServeHTTP(w, r)
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) == 0 {
			w.Header().Set("WWW-Authenticate", challengeBearer)
			writeProblem(w, r, problem.New(problem.CodeUnauthenticated))
			return
		}
		ctx := r.Context()
		ip := middleware.ClientIP(ctx)
		authCtx, err := a.authenticate(ctx, values, ip)
		if err == nil {
			r = r.WithContext(authCtx)
			r.Header = r.Header.Clone()
			r.Header.Del("Cookie")
			next.ServeHTTP(w, r)
			return
		}
		var refused *provisioning.AuthError
		if !errors.As(err, &refused) {
			level := slog.LevelError
			if middleware.ClientGone(ctx, err) {
				level = slog.LevelDebug // the client went away
			}
			a.logger.Log(ctx, level, "provisioning token lookup failed",
				slog.String("request_id", middleware.RequestID(ctx)), slog.String("error", err.Error()))
			refuseProvisioning(w, r)
			return
		}
		key := middleware.RateLimitKey(ip)
		if locked, retry := a.failures.Locked(key); locked {
			if ok, _ := a.throttle.Allow(key); ok {
				a.events.RateLimited(ctx, ip, "", ScopeProvisioningToken)
			}
			writeProblem(w, r, problem.New(problem.CodeRateLimited, problem.WithRetryAfter(retry)))
			return
		}
		a.events.ProvisioningTokenInvalid(ctx, ip)
		a.failures.Fail(key)
		attrs := []any{slog.String("request_id", middleware.RequestID(ctx)), slog.String("reason", refused.Reason)}
		if refused.TokenID != "" {
			attrs = append(attrs, slog.String("token", refused.TokenID))
		}
		a.logger.InfoContext(ctx, "provisioning token refused", attrs...)
		refuseProvisioning(w, r)
	})
}

// authenticate checks the Authorization header values of a request from
// ip: exactly one non-empty Bearer credential, accepted by the
// authenticator. A refusal decided here is a *provisioning.AuthError with
// one of the reasons above.
func (a *provisioningAuth) authenticate(ctx context.Context, values []string, ip netip.Addr) (context.Context, error) {
	if len(values) != 1 {
		// Several Authorization headers: ambiguous, refused.
		return nil, &provisioning.AuthError{Reason: reasonMalformedHeader}
	}
	raw, ok := bearerToken(values[0])
	if !ok {
		return nil, &provisioning.AuthError{Reason: reasonMalformedHeader}
	}
	if a.auth == nil {
		return nil, &provisioning.AuthError{Reason: reasonNoService}
	}
	return a.auth.AuthenticateProvisioning(ctx, raw, ip)
}

// refuseProvisioning answers 401 provisioning-token-invalid.
func refuseProvisioning(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", challengeInvalidToken)
	writeProblem(w, r, problem.New(problem.CodeProvisioningTokenInvalid))
}

// bearerToken returns the token of an Authorization header of the Bearer
// scheme (case-insensitive scheme name), and whether there is a non-empty
// one.
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

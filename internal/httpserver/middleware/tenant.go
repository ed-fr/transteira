package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ScopeUnknownHost is the rate-limit scope reported when requests for
// unknown hosts are throttled by [Tenant].
const ScopeUnknownHost = "unknown_host"

// errNoTenant reports a resolver returning neither a tenant nor an error.
var errNoTenant = errors.New("middleware: resolver returned no tenant and no error")

// maxLoggedHost bounds the length of a host name passed to
// SecurityEvents.UnknownFQDN (a DNS name is at most 253 bytes, plus a port).
const maxLoggedHost = 260

// Tenant resolves the tenant from the raw Host header (r.Host) and stores
// it in the request context with [tenant.WithTenant]. There is no default
// tenant (threat model T-02).
//
// X-Forwarded-Host, Forwarded and any other header are ignored entirely:
// the reverse proxy must pass the original Host through, as the provided
// proxy configurations do, so that there is a single source of truth and
// no ambiguity between proxy and application (T-04). Absolute URLs in
// e-mails are built from the tenant's registered FQDN, never from Host
// (T-03).
//
// An unknown or malformed host gets a 421 unknown-tenant Problem and an
// UnknownFQDN security event with the client IP and the host (truncated).
// When unknownLimiter is not nil, each such request also consumes a token
// keyed by client IP; once it is denied, the request gets a 429
// rate-limited Problem and a RateLimited event (scope [ScopeUnknownHost])
// instead of the UnknownFQDN event, so that floods of random hosts are
// throttled and banned. Every 421 up to the limit is logged, so that
// fail2ban and CrowdSec see host scans; once the client is refused with
// 429, at most one RateLimited event per key is written every
// [SecurityEventInterval] (see [RateLimit]) and no UnknownFQDN event is
// written. Without unknownLimiter, every unknown host is logged. Any
// other resolver error yields a 500 internal-error Problem; the error is
// logged on logger (nil discards) and never sent to the client.
//
// events must not be nil. Tenant must run inside [RealIP].
func Tenant(resolver TenantResolver, events SecurityEvents, unknownLimiter Limiter, logger *slog.Logger) func(http.Handler) http.Handler {
	return tenantMiddleware(resolver, events, unknownLimiter, logger, time.Now)
}

// tenantMiddleware is Tenant with an injectable clock for the event
// throttle.
func tenantMiddleware(resolver TenantResolver, events SecurityEvents, unknownLimiter Limiter, logger *slog.Logger, clock func() time.Time) func(http.Handler) http.Handler {
	if resolver == nil || events == nil {
		panic("middleware: Tenant requires a resolver and security events")
	}
	logger = orDiscard(logger)
	throttle := newEventThrottle(clock)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			t, err := resolver.Resolve(ctx, r.Host)
			switch {
			case err == nil && t != nil:
				next.ServeHTTP(w, r.WithContext(tenant.WithTenant(ctx, t)))
			case errors.Is(err, tenant.ErrUnknownTenant), errors.Is(err, tenant.ErrInvalidHost):
				if unknownLimiter != nil && !allow(w, r, unknownLimiter, events, throttle, ScopeUnknownHost) {
					return
				}
				events.UnknownFQDN(ctx, ClientIP(ctx), truncateHost(r.Host))
				writeProblem(w, r, problem.CodeUnknownTenant)
			default:
				if err == nil {
					err = errNoTenant
				}
				logger.Log(ctx, failureLevel(ctx, err), "tenant resolution failed",
					slog.String("request_id", requestIDOf(w, r)),
					slog.String("error", err.Error()),
				)
				writeProblem(w, r, problem.CodeInternalError)
			}
		})
	}
}

// truncateHost cuts host to at most maxLoggedHost bytes without splitting a
// UTF-8 sequence. Escaping is the security log's job.
func truncateHost(host string) string {
	if len(host) <= maxLoggedHost {
		return host
	}
	cut := maxLoggedHost
	for cut > 0 && !utf8.RuneStart(host[cut]) {
		cut--
	}
	return host[:cut]
}

// Compile-time check that the tenant resolver satisfies TenantResolver.
var _ TenantResolver = (*tenant.Resolver)(nil)

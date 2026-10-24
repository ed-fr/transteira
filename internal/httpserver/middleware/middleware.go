package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TenantResolver maps a raw Host header value to the tenant serving it. It
// returns an error wrapping [tenant.ErrInvalidHost] for a malformed host and
// [tenant.ErrUnknownTenant] when no tenant serves it. [tenant.Resolver]
// implements it.
type TenantResolver interface {
	Resolve(ctx context.Context, host string) (*tenant.Tenant, error)
}

// SecurityEvents receives the security events raised by the middlewares, to
// be written to the security log consumed by fail2ban and CrowdSec. ip is
// always the real client IP computed by [RealIP]; it may be the zero Addr
// when the peer address could not be parsed. Implementations must escape
// every string argument, which is attacker-controlled.
type SecurityEvents interface {
	// UnknownFQDN records a request whose Host header matches no tenant.
	UnknownFQDN(ctx context.Context, ip netip.Addr, host string)
	// RateLimited records a request refused by a rate limiter. tenantFQDN
	// is empty when no tenant is known yet; scope names the limiter.
	RateLimited(ctx context.Context, ip netip.Addr, tenantFQDN, scope string)
}

// Limiter is a keyed rate limiter. Allow consumes one token for key and
// reports whether the request may proceed and, if not, how long the caller
// should wait before retrying.
type Limiter interface {
	Allow(key string) (ok bool, retryAfter time.Duration)
}

// Chain wraps h with mws. The first middleware is the outermost one: it sees
// the request first and the response last.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// writeProblem renders a Problem for code carrying the request identifier
// as instance.
func writeProblem(w http.ResponseWriter, r *http.Request, code problem.Code, opts ...problem.Option) {
	opts = append(opts, problem.WithInstance(requestIDOf(w, r)))
	problem.Write(w, problem.New(code, opts...))
}

// requestIDOf returns the request identifier from the context or, when the
// caller sits outside [AssignRequestID] (as [Recover] does), from the response
// header that AssignRequestID sets.
func requestIDOf(w http.ResponseWriter, r *http.Request) string {
	if id := RequestID(r.Context()); id != "" {
		return id
	}
	return w.Header().Get(HeaderRequestID)
}

// tenantFQDN returns the FQDN of the tenant carried by ctx, or "".
func tenantFQDN(ctx context.Context) string {
	if t, ok := tenant.FromContext(ctx); ok {
		return t.FQDN
	}
	return ""
}

// orDiscard returns l, or a logger discarding everything when l is nil.
func orDiscard(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.DiscardHandler)
	}
	return l
}

// ClientGone reports whether err is the request context's own error
// (context.Canceled, or context.DeadlineExceeded for a context carrying a
// deadline) after that context ended: the client canceled the request or
// went away while it was served. Such a failure is not a server fault and
// is logged at Debug level only. The request deadlines of TransTeira are
// connection deadlines, which never end the request context.
func ClientGone(ctx context.Context, err error) bool {
	return ctx.Err() != nil && errors.Is(err, ctx.Err())
}

// failureLevel returns the level at which a failure err of the request
// whose context is ctx is logged: Debug when the client went away
// ([ClientGone]), Error otherwise.
func failureLevel(ctx context.Context, err error) slog.Level {
	if ClientGone(ctx, err) {
		return slog.LevelDebug
	}
	return slog.LevelError
}

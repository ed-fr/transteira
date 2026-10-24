package middleware

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// RateLimit refuses requests once limiter denies the client IP computed by
// [RealIP] (so it must run inside RealIP). A refused request yields a 429
// rate-limited Problem with a Retry-After header, and a RateLimited
// security event tagged with scope and, when known, the tenant FQDN.
// Events are throttled: at most one per key and scope every
// [SecurityEventInterval]; every refused request still gets its 429.
// A nil events disables the event; a nil limiter panics, being a wiring
// error.
//
// Keys are computed by [RateLimitKey]: IPv6 clients are limited per /64,
// and requests without a valid client IP share one bucket.
func RateLimit(limiter Limiter, events SecurityEvents, scope string) func(http.Handler) http.Handler {
	return rateLimit(limiter, events, scope, time.Now)
}

// RateLimitIf is [RateLimit] applied only to the requests for which
// required returns true; the others pass without consuming a token. It
// serves per-operation limits, such as the admin login steps on top of the
// global limit (run where the operation is known: a per-operation
// middleware of the API router), or the global and asset limits with
// complementary predicates, so that each request is charged to exactly one
// of them.
func RateLimitIf(limiter Limiter, events SecurityEvents, scope string, required func(*http.Request) bool) func(http.Handler) http.Handler {
	return rateLimitIf(limiter, events, scope, required, time.Now)
}

// rateLimit is RateLimit with an injectable clock for the event throttle.
func rateLimit(limiter Limiter, events SecurityEvents, scope string, clock func() time.Time) func(http.Handler) http.Handler {
	return rateLimitIf(limiter, events, scope, func(*http.Request) bool { return true }, clock)
}

// rateLimitIf implements RateLimit and RateLimitIf.
func rateLimitIf(limiter Limiter, events SecurityEvents, scope string, required func(*http.Request) bool, clock func() time.Time) func(http.Handler) http.Handler {
	if limiter == nil {
		panic("middleware: RateLimit requires a limiter")
	}
	throttle := newEventThrottle(clock)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if required(r) && !allow(w, r, limiter, events, throttle, scope) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allow consumes one token of limiter for the client IP. When the request
// is denied, it records the event (unless throttle suppresses it), writes
// the 429 response and returns false.
func allow(w http.ResponseWriter, r *http.Request, limiter Limiter, events SecurityEvents, throttle *eventThrottle, scope string) bool {
	ip := ClientIP(r.Context())
	key := RateLimitKey(ip)
	ok, retry := limiter.Allow(key)
	if ok {
		return true
	}
	if events != nil && throttle.allow(key+" "+scope) {
		events.RateLimited(r.Context(), ip, tenantFQDN(r.Context()), scope)
	}
	writeProblem(w, r, problem.CodeRateLimited, problem.WithRetryAfter(retry))
	return false
}

// invalidKey is the single bucket shared by requests without a valid
// client IP.
const invalidKey = "invalid"

// RateLimitKey returns the rate-limit bucket key of a client IP: the IPv4
// address itself, or the /64 prefix of an IPv6 address (for example
// "2001:db8:1:2::/64"), because a single IPv6 subscriber usually owns a
// whole /64 and could otherwise rotate addresses to evade per-IP limits.
// IPv4-mapped addresses are unmapped and zones ignored. An invalid (zero)
// address maps to one shared bucket, "invalid".
func RateLimitKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return invalidKey
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	p, _ := ip.Prefix(64) // cannot fail: 64 bits fit an IPv6 address
	return p.String()
}

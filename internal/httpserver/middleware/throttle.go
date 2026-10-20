package middleware

import (
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/ratelimit"
)

// SecurityEventInterval is the minimum interval between two security
// events of the same kind for the same rate-limit key. While a client keeps
// being refused with 429 responses, [RateLimit] writes at most one
// rate_limited event per key ([RateLimitKey] of the client IP) and scope
// per interval, so that a flood cannot fill the security log or the disk.
// One event per interval is enough for fail2ban and CrowdSec to keep
// counting the offender. The 429 responses themselves are not affected.
const SecurityEventInterval = 10 * time.Second

// eventThrottle decides whether a security event may be written. It allows
// one event per key per SecurityEventInterval. Memory is bounded by the
// ratelimit table (LRU with idle expiry). It is safe for concurrent use.
type eventThrottle struct {
	lim *ratelimit.Limiter
}

// newEventThrottle returns an eventThrottle reading the time from clock
// (time.Now when nil).
func newEventThrottle(clock func() time.Time) *eventThrottle {
	return &eventThrottle{lim: ratelimit.New(rate.Every(SecurityEventInterval), 1, ratelimit.WithClock(clock))}
}

// allow reports whether an event for key may be written now.
func (t *eventThrottle) allow(key string) bool {
	ok, _ := t.lim.Allow(key)
	return ok
}

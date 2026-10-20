// Package ratelimit provides bounded, concurrency-safe, per-key rate
// limiting primitives: token buckets (Limiter) and sliding windows with
// optional lockout (Window). Memory is bounded by a table with idle expiry
// and a capped number of keys, and the clock is injectable for tests.
//
// All state is kept in memory and is lost when the process restarts: a
// restart clears every counter and every lockout. This is acceptable for
// coarse abuse protection (request floods, unknown hosts), but the
// security-critical counters of the specification (failed verification-code
// attempts, transfer-password lockouts) should be persisted in the database
// when those features are built, or the loss on restart must be explicitly
// accepted; a Window can then serve as a fast front cache.
package ratelimit

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a set of token buckets, one per key (IP address, API token,
// e-mail address...). It is safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	clock   func() time.Time
	buckets *table[*rate.Limiter]
}

// New returns a Limiter refilling each key at r events per second up to
// burst tokens. r must be positive (rate.Inf disables limiting) and burst at
// least 1; New panics otherwise since this is a programming error.
func New(r rate.Limit, burst int, opts ...Option) *Limiter {
	if r <= 0 || burst < 1 {
		panic("ratelimit: rate must be positive and burst at least 1")
	}
	c := newConfig(opts)
	if c.idleTTL <= 0 {
		c.idleTTL = fullRefill(r, burst)
	}
	return &Limiter{
		limit:   r,
		burst:   burst,
		clock:   c.clock,
		buckets: newTable(c.maxKeys, c.idleTTL, bucketRank(burst)),
	}
}

// bucketRank ranks token buckets for eviction. Forgetting a bucket gives the
// key a fresh, full bucket, so full buckets are evicted first (lossless),
// then partially used ones, and buckets currently denying events last.
// Buckets are never protected absolutely: a full table always admits a new
// key, falling back to plain LRU among the inspected entries.
func bucketRank(burst int) rankFunc[*rate.Limiter] {
	return func(b *rate.Limiter, now time.Time) int {
		switch tokens := b.TokensAt(now); {
		case tokens >= float64(burst):
			return 0
		case tokens >= 1:
			return 1
		default:
			return 2
		}
	}
}

// fullRefill returns the time needed to refill an empty bucket, which is the
// shortest idle period after which a bucket can be forgotten losslessly.
func fullRefill(r rate.Limit, burst int) time.Duration {
	ns := float64(burst) / float64(r) * float64(time.Second)
	if ns >= math.MaxInt64 {
		return time.Duration(math.MaxInt64)
	}
	return max(time.Duration(ns), time.Nanosecond)
}

// Allow consumes one token for key. It reports whether the event is allowed
// and, when it is not, how long to wait before retrying (whole seconds,
// at least one second, suitable for a Retry-After header).
//
// When the key table is full, a new key evicts the least recently used
// bucket among those that are full, else partially used, else denying (see
// WithMaxKeys). Evicting a denying bucket resets it, which an attacker
// controlling many keys could exploit; use a Window for limits that must
// fail closed.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	// bucketRank never returns rankNever, so get always admits the key.
	b, _, _ := l.buckets.get(key, now, func() *rate.Limiter {
		return rate.NewLimiter(l.limit, l.burst)
	})
	if b.AllowN(now, 1) {
		return true, 0
	}
	missing := 1 - b.TokensAt(now)
	return false, roundUp(time.Duration(missing / float64(l.limit) * float64(time.Second)))
}

// Len returns the number of keys currently tracked.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets.expire(l.clock())
	return l.buckets.len()
}

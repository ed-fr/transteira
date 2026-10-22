package ratelimit

import (
	"sync"
	"time"
)

// MaxWindowLimit is the largest limit accepted by NewWindow. A Window keeps
// the timestamp of every counted event, so its memory grows with the limit;
// use a Limiter (token bucket) for high-volume limits.
const MaxWindowLimit = 256

// Window counts events per key over a sliding window of a given period, and
// can lock a key out after too many failures. It covers rules such as
// "5 codes per hour per address" (Allow) or "3 failed attempts, then a
// 15-minute lock" (Fail, Locked, Reset). It is safe for concurrent use.
//
// The window is exact: it keeps the timestamps of the events of the last
// period, so no span of one period ever contains more than limit counted
// events, including across what would be the boundary of a fixed window.
// Memory is bounded by the number of keys times the limit.
//
// Window fails closed when its key table is full (see WithMaxKeys): a key
// that is locked or has reached its limit is never evicted, so an attacker
// cannot clear their own lock by churning through many keys (IPv6
// addresses, e-mail addresses...). Idle keys are evicted first, then keys
// with failures below the limit (which loses that partial count). When every
// inspected key is locked or at its limit, a new key is refused (Allow
// returns false, Fail returns true) until a slot frees up. This trade-off is
// deliberate: a flood of restricted keys can make new keys be refused for a
// while, but memory stays bounded and no lock is ever lifted early.
//
// State is lost on restart; see the package documentation.
type Window struct {
	mu      sync.Mutex
	limit   int
	period  time.Duration
	lockout time.Duration
	clock   func() time.Time
	states  *table[*windowState]
}

// windowState is the counter of one key.
type windowState struct {
	events      []time.Time // counted events of the last period, oldest first
	lockedUntil time.Time
}

// NewWindow returns a Window allowing limit events per key within any
// period. limit must be between 1 and MaxWindowLimit and period positive;
// NewWindow panics otherwise since this is a programming error. WithLockout
// sets the lock duration used by Fail (default: period).
func NewWindow(limit int, period time.Duration, opts ...Option) *Window {
	if limit < 1 || limit > MaxWindowLimit || period <= 0 {
		panic("ratelimit: limit must be between 1 and MaxWindowLimit and period positive")
	}
	c := newConfig(opts)
	if c.lockout <= 0 {
		c.lockout = period
	}
	// Idle expiry must never forget a key before its events leave the window
	// or its lock ends, whatever WithIdleTTL asked for.
	c.idleTTL = max(c.idleTTL, period, c.lockout)
	w := &Window{
		limit:   limit,
		period:  period,
		lockout: c.lockout,
		clock:   c.clock,
	}
	w.states = newTable(c.maxKeys, c.idleTTL, w.rank)
	return w
}

// prune drops the events of s that left the window at now: an event at t
// counts while now is before t+period.
func (w *Window) prune(s *windowState, now time.Time) {
	k := 0
	for k < len(s.events) && !now.Before(s.events[k].Add(w.period)) {
		k++
	}
	if k > 0 {
		s.events = s.events[:copy(s.events, s.events[k:])]
	}
}

// rank ranks a key for eviction: idle keys first, then keys below their
// limit; locked keys and keys at their limit are never evicted.
func (w *Window) rank(s *windowState, now time.Time) int {
	w.prune(s, now)
	switch {
	case lockRemaining(s, now) > 0 || len(s.events) >= w.limit:
		return rankNever
	case len(s.events) > 0:
		return 1
	default:
		return 0
	}
}

// state returns the up-to-date state of key. ok is false when the key is
// unknown and the table is full of keys that must be kept; retryAfter then
// says when a slot will have freed up.
func (w *Window) state(key string, now time.Time) (s *windowState, ok bool, retryAfter time.Duration) {
	s, ok, retryAfter = w.states.get(key, now, func() *windowState {
		return &windowState{}
	})
	if ok {
		w.prune(s, now)
	}
	return s, ok, retryAfter
}

// lockRemaining returns the remaining lock of s at now, or zero.
func lockRemaining(s *windowState, now time.Time) time.Duration {
	if now.Before(s.lockedUntil) {
		return roundUp(s.lockedUntil.Sub(now))
	}
	return 0
}

// Allow records one event for key if fewer than limit events were counted
// within the last period. When the event is refused (limit reached, key
// locked, or key table full of restricted keys), it returns false with the
// time until an event leaves the window or the lock ends, in whole seconds,
// at least one second.
func (w *Window) Allow(key string) (ok bool, retryAfter time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock()
	s, ok, retryAfter := w.state(key, now)
	if !ok {
		return false, retryAfter
	}
	if d := lockRemaining(s, now); d > 0 {
		return false, d
	}
	if n := len(s.events); n >= w.limit {
		return false, roundUp(s.events[n-w.limit].Add(w.period).Sub(now))
	}
	s.events = append(s.events, now)
	return true, 0
}

// Refund takes back the most recent event counted for key by Allow, for
// an operation that reserved its slot first and then failed before doing
// anything. It does nothing when no event of key is counted any more.
func (w *Window) Refund(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock()
	s, ok := w.states.peek(key, now)
	if !ok {
		return
	}
	w.prune(s, now)
	if n := len(s.events); n > 0 {
		s.events = s.events[:n-1]
	}
}

// Fail records one failure for key. When the number of failures within the
// last period reaches the limit, the key is locked for the lockout duration
// and Fail returns true with the remaining lock. Failures recorded while the
// key is locked do not extend the lock. When the key table is full of
// restricted keys, Fail fails closed and reports the key as locked.
func (w *Window) Fail(key string) (locked bool, retryAfter time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock()
	s, ok, retryAfter := w.state(key, now)
	if !ok {
		return true, retryAfter
	}
	if d := lockRemaining(s, now); d > 0 {
		return true, d
	}
	s.events = append(s.events, now)
	if len(s.events) < w.limit {
		return false, 0
	}
	s.events = s.events[:0]
	s.lockedUntil = now.Add(w.lockout)
	return true, roundUp(w.lockout)
}

// Locked reports whether key is currently locked and for how long, without
// recording anything.
func (w *Window) Locked(key string) (locked bool, retryAfter time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock()
	s, ok := w.states.peek(key, now)
	if !ok {
		return false, 0
	}
	d := lockRemaining(s, now)
	return d > 0, d
}

// Reset forgets key: its counter and any lock are cleared, for instance
// after a successful attempt.
func (w *Window) Reset(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.states.delete(key)
}

// Len returns the number of keys currently tracked.
func (w *Window) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.states.expire(w.clock())
	return w.states.len()
}

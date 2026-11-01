// Package touchthrottle throttles the recording of the last use of a
// credential (API tokens, provisioning tokens): the first use seen by the
// process is recorded, then at most one per interval per credential, so
// that a busy token does not write to the database on every request.
package touchthrottle

import (
	"sync"
	"time"
)

// Defaults of [New].
const (
	// DefaultInterval is the minimum delay between two recordings of the
	// last use of a credential.
	DefaultInterval = time.Minute
	// DefaultMaxTracked bounds the number of credentials whose last
	// recording is remembered.
	DefaultMaxTracked = 10000
)

// Throttle remembers when the last use of each credential was recorded.
// It is safe for concurrent use. State is lost on restart, which only
// causes one extra recording per credential.
type Throttle struct {
	interval   time.Duration
	maxTracked int
	mu         sync.Mutex
	touched    map[string]time.Time
}

// New returns a Throttle recording at most one use per interval per
// credential and remembering at most maxTracked credentials. interval <= 0
// means DefaultInterval and maxTracked <= 0 DefaultMaxTracked.
func New(interval time.Duration, maxTracked int) *Throttle {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if maxTracked <= 0 {
		maxTracked = DefaultMaxTracked
	}
	return &Throttle{interval: interval, maxTracked: maxTracked, touched: map[string]time.Time{}}
}

// Interval returns the minimum delay between two recordings.
func (t *Throttle) Interval() time.Duration { return t.interval }

// MaxTracked returns the bound of the remembered credentials.
func (t *Throttle) MaxTracked() int { return t.maxTracked }

// Due reports whether the use of credential key at now must be recorded,
// and remembers it when so: the first use seen by this process, then at
// most one per interval (a clock going backwards records again). The
// memory is bounded by maxTracked: when it is full, the entries older than
// the interval are dropped, and if none is, all of them (the next uses are
// then recorded again, which is harmless).
func (t *Throttle) Due(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.touched[key]
	if ok && now.Sub(last) < t.interval && !now.Before(last) {
		return false
	}
	if !ok && len(t.touched) >= t.maxTracked {
		for k, at := range t.touched {
			if now.Sub(at) >= t.interval {
				delete(t.touched, k)
			}
		}
		if len(t.touched) >= t.maxTracked {
			clear(t.touched)
		}
	}
	t.touched[key] = now
	return true
}

// Forget drops the memory of credential key (revoked).
func (t *Throttle) Forget(key string) {
	t.mu.Lock()
	delete(t.touched, key)
	t.mu.Unlock()
}

// Tracked reports whether credential key is remembered.
func (t *Throttle) Tracked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.touched[key]
	return ok
}

// Len returns the number of remembered credentials.
func (t *Throttle) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.touched)
}

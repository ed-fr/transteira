package ratelimit

import (
	"container/list"
	"math"
	"time"
)

// DefaultMaxKeys is the default upper bound on the number of keys tracked
// by a Limiter or a Window.
const DefaultMaxKeys = 100_000

// config holds the settings shared by Limiter and Window.
type config struct {
	maxKeys int
	clock   func() time.Time
	idleTTL time.Duration
	lockout time.Duration
}

// Option customizes a Limiter or a Window.
type Option func(*config)

// WithMaxKeys bounds the number of keys kept in memory. When the bound is
// reached, a key is evicted to make room, preferring keys whose loss cannot
// relax a limit (see Limiter.Allow and Window for the exact policy). Values
// below 1 are ignored.
func WithMaxKeys(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxKeys = n
		}
	}
}

// WithClock injects the time source, mainly for tests. A nil clock is
// ignored.
func WithClock(clock func() time.Time) Option {
	return func(c *config) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// WithIdleTTL evicts keys that have not been used for d. The default is the
// shortest duration after which forgetting a key cannot change any decision
// (full bucket refill for a Limiter, end of window or lockout for a Window).
// Values below or equal to zero are ignored.
func WithIdleTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.idleTTL = d
		}
	}
}

// WithLockout sets how long a key stays locked once Window.Fail has reached
// the limit. It defaults to the window period and only applies to Window.
// Values below or equal to zero are ignored.
func WithLockout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.lockout = d
		}
	}
}

func newConfig(opts []Option) config {
	c := config{maxKeys: DefaultMaxKeys, clock: time.Now}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// maxEvictScan bounds how many of the least recently used entries are
// inspected to choose an eviction victim, so that admitting a key into a full
// table stays O(1) even when most entries must not be evicted.
const maxEvictScan = 256

// rankNever marks an entry that must never be evicted (for instance an
// active lockout): a table whose candidates all have this rank refuses new
// keys instead of evicting one (fail closed).
const rankNever = math.MaxInt

// rankFunc ranks an entry for eviction at now: the lower the rank, the
// cheaper it is to forget the entry. rankNever forbids the eviction.
type rankFunc[V any] func(v V, now time.Time) int

// entry is one key of a table.
type entry[V any] struct {
	key      string
	value    V
	lastSeen time.Time
}

// table is a bounded LRU map with idle expiry. All operations are O(1)
// amortized. It is not safe for concurrent use; callers hold their own lock.
//
// When the table is full, the victim is the lowest-ranked entry among the
// maxEvictScan least recently used ones (the least recently used wins ties).
// If every inspected entry has
// rankNever, the new key is refused rather than an entry evicted.
type table[V any] struct {
	maxKeys int
	idleTTL time.Duration
	rank    rankFunc[V]
	items   map[string]*list.Element
	order   *list.List // front = most recently used
}

func newTable[V any](maxKeys int, idleTTL time.Duration, rank rankFunc[V]) *table[V] {
	return &table[V]{
		maxKeys: maxKeys,
		idleTTL: idleTTL,
		rank:    rank,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

// expire removes the keys idle for at least idleTTL at now. The list is
// ordered by last use, so only the oldest entries are inspected.
func (t *table[V]) expire(now time.Time) {
	for back := t.order.Back(); back != nil; back = t.order.Back() {
		if now.Sub(back.Value.(*entry[V]).lastSeen) < t.idleTTL {
			return
		}
		t.remove(back)
	}
}

// victim returns the entry to evict to make room at now, or nil when every
// inspected entry must be kept.
func (t *table[V]) victim(now time.Time) *list.Element {
	var best *list.Element
	bestRank := rankNever
	for el, n := t.order.Back(), 0; el != nil && n < maxEvictScan; el, n = el.Prev(), n+1 {
		r := t.rank(el.Value.(*entry[V]).value, now)
		if r < bestRank {
			best, bestRank = el, r
			if r == 0 {
				break
			}
		}
	}
	return best
}

// get returns the value stored for key, creating it with create when absent,
// and marks the key as used at now. When the key is absent and the table is
// full of entries that must not be evicted, get returns ok == false and the
// time after which the least recently used entry expires, freeing a slot.
func (t *table[V]) get(key string, now time.Time, create func() V) (v V, ok bool, retryAfter time.Duration) {
	t.expire(now)
	if el, found := t.items[key]; found {
		e := el.Value.(*entry[V])
		e.lastSeen = now
		t.order.MoveToFront(el)
		return e.value, true, 0
	}
	for len(t.items) >= t.maxKeys {
		el := t.victim(now)
		if el == nil {
			oldest := t.order.Back().Value.(*entry[V]).lastSeen
			return v, false, roundUp(t.idleTTL - now.Sub(oldest))
		}
		t.remove(el)
	}
	e := &entry[V]{key: key, value: create(), lastSeen: now}
	t.items[key] = t.order.PushFront(e)
	return e.value, true, 0
}

// peek returns the value stored for key without creating it or refreshing
// its recency.
func (t *table[V]) peek(key string, now time.Time) (V, bool) {
	t.expire(now)
	el, ok := t.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	return el.Value.(*entry[V]).value, true
}

// delete forgets key.
func (t *table[V]) delete(key string) {
	if el, ok := t.items[key]; ok {
		t.remove(el)
	}
}

func (t *table[V]) remove(el *list.Element) {
	delete(t.items, el.Value.(*entry[V]).key)
	t.order.Remove(el)
}

func (t *table[V]) len() int { return len(t.items) }

// roundUp converts a wait into a Retry-After friendly duration: whole
// seconds, rounded up, never below one second.
func roundUp(d time.Duration) time.Duration {
	if d <= time.Second {
		return time.Second
	}
	return (d + time.Second - 1).Truncate(time.Second)
}

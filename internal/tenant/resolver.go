package tenant

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Default resolver settings.
const (
	// DefaultPositiveTTL bounds how long a resolved tenant is served from the
	// cache. Explicit invalidation is the primary mechanism; the TTL is a
	// safety net against a missed invalidation.
	DefaultPositiveTTL = 10 * time.Minute
	// DefaultNegativeTTL is how long an unknown host is remembered.
	DefaultNegativeTTL = 30 * time.Second
	// DefaultMaxNegativeEntries bounds the number of remembered unknown hosts.
	DefaultMaxNegativeEntries = 10_000
)

// ErrUnknownTenant reports that no tenant serves the requested host. There
// is no fallback tenant: callers must reject the request.
var ErrUnknownTenant = errors.New("tenant: unknown tenant")

// errLookupMismatch reports a Lookup result whose FQDN differs from the
// requested one.
var errLookupMismatch = errors.New("tenant: lookup returned a tenant for another fqdn")

// Lookup finds a tenant by its normalised FQDN. Implementations return an
// error wrapping ErrUnknownTenant when no tenant matches.
type Lookup interface {
	TenantByFQDN(ctx context.Context, fqdn string) (*Tenant, error)
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithPositiveTTL sets how long a resolved tenant is cached. A value <= 0
// disables positive caching: every Resolve queries the Lookup.
func WithPositiveTTL(d time.Duration) Option {
	return func(r *Resolver) { r.posTTL = d }
}

// WithNegativeTTL sets how long an unknown host is cached. A value <= 0
// disables negative caching.
func WithNegativeTTL(d time.Duration) Option {
	return func(r *Resolver) { r.negTTL = d }
}

// WithMaxNegativeEntries bounds the negative cache. A value <= 0 disables
// negative caching.
func WithMaxNegativeEntries(n int) Option {
	return func(r *Resolver) { r.negMax = n }
}

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Resolver) { r.now = now }
}

// posEntry is a cached tenant with its expiry.
type posEntry struct {
	t   *Tenant
	exp time.Time
}

// negEntry is an element of the negative cache FIFO.
type negEntry struct {
	fqdn string
	exp  time.Time
}

// Resolver maps HTTP Host header values to tenants, with an in-memory cache.
// TransTeira runs as a single instance (CLAUDE.md §4), so explicit
// invalidation after each administrative change keeps the cache exact.
// A Resolver is safe for concurrent use.
type Resolver struct {
	lookup Lookup
	posTTL time.Duration
	negTTL time.Duration
	negMax int
	now    func() time.Time

	mu       sync.RWMutex
	gen      uint64 // bumped by every invalidation
	positive map[string]posEntry
	negative map[string]time.Time // fqdn -> expiry
	negQueue []negEntry           // insertion (hence expiry) order, at most negMax
}

// NewResolver returns a Resolver backed by lookup. It panics if lookup is
// nil, which is a wiring error detected at start-up.
func NewResolver(lookup Lookup, opts ...Option) *Resolver {
	if lookup == nil {
		panic("tenant: NewResolver called with a nil Lookup")
	}
	r := &Resolver{
		lookup:   lookup,
		posTTL:   DefaultPositiveTTL,
		negTTL:   DefaultNegativeTTL,
		negMax:   DefaultMaxNegativeEntries,
		now:      time.Now,
		positive: make(map[string]posEntry),
		negative: make(map[string]time.Time),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolve normalises host and returns a copy of the tenant serving it.
// It returns an error wrapping ErrInvalidHost for a malformed host and
// ErrUnknownTenant when no tenant serves it. Other lookup errors are
// returned wrapped and are not cached.
//
// A lookup result is cached only if no invalidation happened while the
// lookup was in flight, so an invalidation is never lost.
func (r *Resolver) Resolve(ctx context.Context, host string) (*Tenant, error) {
	fqdn, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}

	now := r.now()
	r.mu.RLock()
	pos, hit := r.positive[fqdn]
	exp, neg := r.negative[fqdn]
	gen := r.gen
	r.mu.RUnlock()
	if hit && now.Before(pos.exp) {
		return pos.t.Clone(), nil
	}
	if neg && now.Before(exp) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTenant, fqdn)
	}

	t, err := r.lookup.TenantByFQDN(ctx, fqdn)
	switch {
	case errors.Is(err, ErrUnknownTenant):
		r.rememberUnknown(fqdn, gen)
		return nil, fmt.Errorf("%w: %q", ErrUnknownTenant, fqdn)
	case err != nil:
		return nil, fmt.Errorf("tenant: resolving %q: %w", fqdn, err)
	case t == nil:
		return nil, fmt.Errorf("tenant: resolving %q: lookup returned no tenant", fqdn)
	case t.FQDN != fqdn:
		return nil, fmt.Errorf("%w: %q", errLookupMismatch, fqdn)
	}

	c := t.Clone()
	if r.posTTL > 0 {
		r.mu.Lock()
		if r.gen == gen {
			r.positive[fqdn] = posEntry{t: c, exp: r.now().Add(r.posTTL)}
			delete(r.negative, fqdn)
		}
		r.mu.Unlock()
	}
	return c.Clone(), nil
}

// rememberUnknown caches fqdn as unknown unless an invalidation happened
// since gen was read. The negative cache is a FIFO bounded by negMax:
// expired entries are purged from its head, then the oldest live entries
// are evicted if it is still full. Each entry is pushed and popped once, so
// the cost is amortized O(1).
func (r *Resolver) rememberUnknown(fqdn string, gen uint64) {
	if r.negTTL <= 0 || r.negMax <= 0 {
		return
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gen != gen {
		return
	}
	if exp, ok := r.negative[fqdn]; ok && now.Before(exp) {
		return
	}
	for len(r.negQueue) > 0 && !now.Before(r.negQueue[0].exp) {
		r.popNegative()
	}
	for len(r.negQueue) >= r.negMax {
		r.popNegative()
	}
	exp := now.Add(r.negTTL)
	r.negative[fqdn] = exp
	r.negQueue = append(r.negQueue, negEntry{fqdn: fqdn, exp: exp})
}

// popNegative removes the head of the negative FIFO and its map entry, unless
// the map entry was replaced or invalidated since. The caller holds r.mu.
func (r *Resolver) popNegative() {
	head := r.negQueue[0]
	r.negQueue[0] = negEntry{}
	r.negQueue = r.negQueue[1:]
	if exp, ok := r.negative[head.fqdn]; ok && exp.Equal(head.exp) {
		delete(r.negative, head.fqdn)
	}
}

// Invalidate drops any cached entry, positive or negative, for the given
// host. Call it with both the old and the new FQDN after a tenant's FQDN
// changes, and after creating a tenant.
func (r *Resolver) Invalidate(host string) {
	key := host
	if fqdn, err := NormalizeHost(host); err == nil {
		key = fqdn
	}
	r.mu.Lock()
	r.gen++
	delete(r.positive, key)
	delete(r.negative, key)
	r.mu.Unlock()
}

// InvalidateTenant drops every cached entry pointing to the tenant id, for
// use after the tenant is updated or deleted.
func (r *Resolver) InvalidateTenant(id ID) {
	r.mu.Lock()
	r.gen++
	for k, e := range r.positive {
		if e.t.ID == id {
			delete(r.positive, k)
		}
	}
	r.mu.Unlock()
}

// InvalidateAll empties the cache.
func (r *Resolver) InvalidateAll() {
	r.mu.Lock()
	r.gen++
	r.positive = make(map[string]posEntry)
	r.negative = make(map[string]time.Time)
	r.negQueue = nil
	r.mu.Unlock()
}

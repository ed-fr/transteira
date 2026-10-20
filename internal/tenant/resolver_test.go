package tenant

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLookup is an in-memory Lookup counting its calls.
type fakeLookup struct {
	mu      sync.Mutex
	tenants map[string]*Tenant
	err     error // returned instead of a result when set
	nilOK   bool  // return (nil, nil) for unknown names
	calls   atomic.Int64
}

func newFakeLookup(ts ...Tenant) *fakeLookup {
	f := &fakeLookup{tenants: make(map[string]*Tenant)}
	for i := range ts {
		f.tenants[ts[i].FQDN] = &ts[i]
	}
	return f
}

func (f *fakeLookup) TenantByFQDN(_ context.Context, fqdn string) (*Tenant, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if t, ok := f.tenants[fqdn]; ok {
		return t, nil
	}
	if f.nilOK {
		return nil, nil
	}
	return nil, fmt.Errorf("store: %w", ErrUnknownTenant)
}

func (f *fakeLookup) set(fqdn string, t *Tenant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t == nil {
		delete(f.tenants, fqdn)
		return
	}
	f.tenants[fqdn] = t
}

func (f *fakeLookup) name(fqdn string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tenants[fqdn].Name
}

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func tenantB() Tenant {
	b := validTenant()
	b.ID = validIDB
	b.Name = "Entity B"
	b.FQDN = "transfer.entity-b.example.com"
	return b
}

func TestNewResolverNilLookupPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("NewResolver(nil) did not panic")
		}
	}()
	NewResolver(nil)
}

func TestResolveHitsCacheAndCopies(t *testing.T) {
	t.Parallel()
	look := newFakeLookup(validTenant(), tenantB())
	r := NewResolver(look)
	ctx := context.Background()

	got, err := r.Resolve(ctx, "Transfer.Entity-A.example.com:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ID != validID {
		t.Fatalf("Resolve returned %q", got.ID)
	}
	got.Name = "mutated"

	again, err := r.Resolve(ctx, "transfer.entity-a.example.com.")
	if err != nil || again.Name != "Entity A" {
		t.Fatalf("cache was mutated through a returned tenant: %+v, %v", again, err)
	}
	again.Name = "mutated twice"
	if look.name("transfer.entity-a.example.com") != "Entity A" {
		t.Fatal("lookup's tenant was mutated through the cache")
	}
	if n := look.calls.Load(); n != 1 {
		t.Fatalf("lookup called %d times, want 1", n)
	}

	b, err := r.Resolve(ctx, "transfer.entity-b.example.com")
	if err != nil || b.ID != validIDB {
		t.Fatalf("Resolve B = %+v, %v", b, err)
	}
}

func TestResolveInvalidHost(t *testing.T) {
	t.Parallel()
	look := newFakeLookup(validTenant())
	r := NewResolver(look)
	if _, err := r.Resolve(context.Background(), "192.0.2.1"); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("Resolve(ip) = %v, want ErrInvalidHost", err)
	}
	if look.calls.Load() != 0 {
		t.Fatal("lookup called for an invalid host")
	}
}

func TestResolveNegativeCache(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	look := newFakeLookup()
	r := NewResolver(look, WithClock(clock.Now), WithNegativeTTL(10*time.Second))
	ctx := context.Background()

	for range 3 {
		if _, err := r.Resolve(ctx, "unknown.example.com"); !errors.Is(err, ErrUnknownTenant) {
			t.Fatalf("Resolve unknown = %v", err)
		}
	}
	if n := look.calls.Load(); n != 1 {
		t.Fatalf("lookup called %d times within TTL, want 1", n)
	}

	clock.Advance(10 * time.Second)
	if _, err := r.Resolve(ctx, "unknown.example.com"); !errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("Resolve unknown after TTL = %v", err)
	}
	if n := look.calls.Load(); n != 2 {
		t.Fatalf("lookup called %d times after TTL, want 2", n)
	}

	// Creating the tenant and invalidating the name makes it resolvable at once.
	nt := validTenant()
	nt.FQDN = "unknown.example.com"
	look.set(nt.FQDN, &nt)
	r.Invalidate("UNKNOWN.example.com:80")
	if _, err := r.Resolve(ctx, "unknown.example.com"); err != nil {
		t.Fatalf("Resolve after Invalidate = %v", err)
	}
}

func TestResolveNegativeCacheDisabled(t *testing.T) {
	t.Parallel()
	for _, opt := range []Option{WithNegativeTTL(0), WithMaxNegativeEntries(0)} {
		look := newFakeLookup()
		r := NewResolver(look, opt)
		for range 3 {
			_, _ = r.Resolve(context.Background(), "unknown.example.com")
		}
		if n := look.calls.Load(); n != 3 {
			t.Fatalf("lookup called %d times with negative cache disabled, want 3", n)
		}
		if len(r.negative) != 0 {
			t.Fatal("negative cache filled while disabled")
		}
	}
}

func TestResolveNegativeCacheBounded(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	look := newFakeLookup()
	const maxEntries = 5
	r := NewResolver(look, WithClock(clock.Now), WithMaxNegativeEntries(maxEntries), WithNegativeTTL(time.Minute))
	ctx := context.Background()

	// Fill beyond the bound without expiry: FIFO eviction keeps it bounded
	// and drops the oldest entries first.
	for i := range 20 {
		_, _ = r.Resolve(ctx, fmt.Sprintf("u%d.example.com", i))
		clock.Advance(time.Second)
		if len(r.negative) > maxEntries || len(r.negQueue) > maxEntries {
			t.Fatalf("negative cache has %d/%d entries, max %d", len(r.negative), len(r.negQueue), maxEntries)
		}
	}
	for i := range 20 {
		_, ok := r.negative[fmt.Sprintf("u%d.example.com", i)]
		if ok != (i >= 15) {
			t.Fatalf("eviction order: u%d present=%v", i, ok)
		}
	}
	// Re-remembering a live unknown host is a no-op.
	r.rememberUnknown("u19.example.com", r.gen)
	if len(r.negative) != maxEntries || len(r.negQueue) != maxEntries {
		t.Fatalf("re-remembering changed the cache: %d/%d", len(r.negative), len(r.negQueue))
	}

	// An invalidated then re-cached host leaves a stale FIFO entry whose
	// eviction must not drop the fresh map entry.
	r.Invalidate("u15.example.com")
	_, _ = r.Resolve(ctx, "u15.example.com") // the full FIFO pops the stale u15 head
	if _, ok := r.negative["u15.example.com"]; !ok || len(r.negative) != maxEntries {
		t.Fatalf("fresh entry for u15 dropped by its stale FIFO entry: %v", r.negative)
	}
	if len(r.negQueue) > maxEntries {
		t.Fatalf("FIFO exceeded its bound: %d", len(r.negQueue))
	}

	// Same with the stale entry popped after the fresh one was pushed.
	r3 := NewResolver(look, WithClock(clock.Now), WithMaxNegativeEntries(3))
	_, _ = r3.Resolve(ctx, "a.example.com")
	r3.Invalidate("a.example.com")
	clock.Advance(time.Second)
	_, _ = r3.Resolve(ctx, "a.example.com") // FIFO: a(stale), a
	_, _ = r3.Resolve(ctx, "b.example.com") // FIFO: a(stale), a, b
	_, _ = r3.Resolve(ctx, "c.example.com") // pops a(stale) only
	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, ok := r3.negative[h]; !ok {
			t.Fatalf("%s missing after stale eviction: %v", h, r3.negative)
		}
	}

	// A remember carrying an outdated generation is discarded.
	r.rememberUnknown("late.example.com", r.gen-1)
	if _, ok := r.negative["late.example.com"]; ok {
		t.Fatal("negative result cached across an invalidation")
	}

	// After expiry, the purge frees room without evicting live entries.
	clock.Advance(time.Minute)
	_, _ = r.Resolve(ctx, "fresh.example.com")
	if len(r.negative) != 1 {
		t.Fatalf("expired entries not purged: %d entries", len(r.negative))
	}

	// With a bound of one, the single live entry is replaced.
	r1 := NewResolver(look, WithClock(clock.Now), WithMaxNegativeEntries(1))
	_, _ = r1.Resolve(ctx, "a.example.com")
	_, _ = r1.Resolve(ctx, "b.example.com")
	if _, ok := r1.negative["b.example.com"]; !ok || len(r1.negative) != 1 {
		t.Fatalf("bound of one not honored: %v", r1.negative)
	}
}

func TestResolveLookupErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("database down")

	look := newFakeLookup()
	look.err = boom
	r := NewResolver(look)
	_, err := r.Resolve(ctx, "transfer.entity-a.example.com")
	if !errors.Is(err, boom) || errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("Resolve with failing lookup = %v", err)
	}
	if len(r.negative) != 0 || len(r.positive) != 0 {
		t.Fatal("lookup failure was cached")
	}

	nilLook := newFakeLookup()
	nilLook.nilOK = true
	if _, err := NewResolver(nilLook).Resolve(ctx, "transfer.entity-a.example.com"); err == nil {
		t.Fatal("Resolve accepted a nil tenant from lookup")
	}

	// A lookup returning a tenant for another FQDN is rejected (defense in depth).
	mis := newFakeLookup()
	b := tenantB()
	mis.set("transfer.entity-a.example.com", &b)
	rm := NewResolver(mis)
	if _, err := rm.Resolve(ctx, "transfer.entity-a.example.com"); !errors.Is(err, errLookupMismatch) {
		t.Fatalf("Resolve with mismatching lookup = %v", err)
	}
	if len(rm.positive) != 0 {
		t.Fatal("mismatching tenant was cached")
	}
}

func TestInvalidate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	look := newFakeLookup(validTenant(), tenantB())
	r := NewResolver(look)
	mustResolve := func(host string) *Tenant {
		t.Helper()
		got, err := r.Resolve(ctx, host)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", host, err)
		}
		return got
	}

	mustResolve("transfer.entity-a.example.com")
	mustResolve("transfer.entity-b.example.com")

	// Rename A in the store: the cache serves the old value until invalidated.
	renamed := validTenant()
	renamed.Name = "Entity A renamed"
	look.set(renamed.FQDN, &renamed)
	if got := mustResolve("transfer.entity-a.example.com"); got.Name != "Entity A" {
		t.Fatalf("unexpected cache miss: %q", got.Name)
	}
	r.Invalidate("transfer.entity-a.example.com")
	if got := mustResolve("transfer.entity-a.example.com"); got.Name != "Entity A renamed" {
		t.Fatalf("Invalidate did not drop the entry: %q", got.Name)
	}

	// Invalidate with an unnormalisable value is harmless.
	r.Invalidate("not a host")

	// InvalidateTenant drops entries by id only.
	r.InvalidateTenant(validIDB)
	if _, ok := r.positive["transfer.entity-b.example.com"]; ok {
		t.Fatal("InvalidateTenant kept tenant B")
	}
	if _, ok := r.positive["transfer.entity-a.example.com"]; !ok {
		t.Fatal("InvalidateTenant dropped tenant A")
	}

	// Removing B from the store makes it unknown once its entry is gone.
	look.set("transfer.entity-b.example.com", nil)
	if _, err := r.Resolve(ctx, "transfer.entity-b.example.com"); !errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("deleted tenant still resolves: %v", err)
	}

	r.InvalidateAll()
	if len(r.positive) != 0 || len(r.negative) != 0 {
		t.Fatal("InvalidateAll left entries")
	}
}

func TestResolverConcurrent(t *testing.T) {
	t.Parallel()
	look := newFakeLookup(validTenant(), tenantB())
	r := NewResolver(look, WithMaxNegativeEntries(50))
	ctx := context.Background()
	hosts := []string{
		"transfer.entity-a.example.com", "transfer.entity-b.example.com:443",
		"unknown.example.com", "192.0.2.1",
	}
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 500 {
				h := hosts[(g+i)%len(hosts)]
				if i%97 == 0 {
					r.Invalidate(h)
				}
				if i%251 == 0 {
					r.InvalidateAll()
				}
				if i%113 == 0 {
					r.InvalidateTenant(validID)
				}
				if i%31 == 0 {
					_, _ = r.Resolve(ctx, fmt.Sprintf("u%d-%d.example.com", g, i))
				}
				got, err := r.Resolve(ctx, h)
				switch {
				case h == "unknown.example.com":
					if !errors.Is(err, ErrUnknownTenant) {
						t.Errorf("unknown host: %v", err)
					}
				case h == "192.0.2.1":
					if !errors.Is(err, ErrInvalidHost) {
						t.Errorf("ip host: %v", err)
					}
				case err != nil:
					t.Errorf("Resolve(%q): %v", h, err)
				default:
					got.Name = "scribble" // must never leak into the cache
				}
			}
		})
	}
	wg.Wait()
	for _, h := range hosts[:2] {
		got, err := r.Resolve(ctx, h)
		if err != nil || got.Name == "scribble" {
			t.Fatalf("cache corrupted for %q: %+v, %v", h, got, err)
		}
	}
	if len(r.negative) > 50 {
		t.Fatalf("negative cache exceeded its bound: %d", len(r.negative))
	}
}

// blockingLookup wraps a Lookup and, when armed, signals entry and waits
// for release before answering.
type blockingLookup struct {
	inner   Lookup
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newBlockingLookup(inner Lookup) *blockingLookup {
	return &blockingLookup{inner: inner, entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockingLookup) TenantByFQDN(ctx context.Context, fqdn string) (*Tenant, error) {
	if b.armed.CompareAndSwap(true, false) {
		b.entered <- struct{}{}
		<-b.release
	}
	return b.inner.TenantByFQDN(ctx, fqdn)
}

// TestResolveInvalidationDuringLookup checks that an invalidation racing a
// lookup is never lost, for each invalidation method and for positive and
// negative results.
func TestResolveInvalidationDuringLookup(t *testing.T) {
	t.Parallel()
	const fqdn = "transfer.entity-a.example.com"
	invalidators := map[string]func(*Resolver){
		"Invalidate":       func(r *Resolver) { r.Invalidate(fqdn) },
		"InvalidateTenant": func(r *Resolver) { r.InvalidateTenant(validID) },
		"InvalidateAll":    func(r *Resolver) { r.InvalidateAll() },
	}
	for name, inv := range invalidators {
		for _, known := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/known=%v", name, known), func(t *testing.T) {
				t.Parallel()
				inner := newFakeLookup()
				if known {
					a := validTenant()
					inner.set(fqdn, &a)
				}
				look := newBlockingLookup(inner)
				r := NewResolver(look)
				look.armed.Store(true)

				done := make(chan error, 1)
				go func() {
					_, err := r.Resolve(context.Background(), fqdn)
					done <- err
				}()
				<-look.entered
				inv(r)
				close(look.release)
				err := <-done
				if known != (err == nil) {
					t.Fatalf("Resolve = %v", err)
				}
				r.mu.RLock()
				_, pos := r.positive[fqdn]
				_, neg := r.negative[fqdn]
				r.mu.RUnlock()
				if pos || neg {
					t.Fatalf("result fetched before the invalidation was cached (pos=%v neg=%v)", pos, neg)
				}
			})
		}
	}
}

// TestResolveFQDNReassignment moves an FQDN from tenant A to tenant B while
// a lookup for it is in flight: B must be served right after.
func TestResolveFQDNReassignment(t *testing.T) {
	t.Parallel()
	const fqdn = "transfer.entity-a.example.com"
	inner := newFakeLookup(validTenant())
	look := newBlockingLookup(inner)
	r := NewResolver(look)
	ctx := context.Background()
	look.armed.Store(true)

	done := make(chan *Tenant, 1)
	go func() {
		got, _ := r.Resolve(ctx, fqdn)
		done <- got
	}()
	<-look.entered
	// The in-flight lookup already read A; the admin reassigns the FQDN to B.
	b := tenantB()
	b.FQDN = fqdn
	inner.set(fqdn, &b)
	r.InvalidateTenant(validID)
	r.Invalidate(fqdn)
	close(look.release)
	<-done

	got, err := r.Resolve(ctx, fqdn)
	if err != nil || got.ID != validIDB {
		t.Fatalf("after reassignment Resolve = %+v, %v", got, err)
	}
}

func TestResolvePositiveTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	look := newFakeLookup(validTenant())
	r := NewResolver(look, WithClock(clock.Now), WithPositiveTTL(time.Minute))
	const fqdn = "transfer.entity-a.example.com"

	_, _ = r.Resolve(ctx, fqdn)
	clock.Advance(59 * time.Second)
	_, _ = r.Resolve(ctx, fqdn)
	if n := look.calls.Load(); n != 1 {
		t.Fatalf("lookup called %d times within TTL, want 1", n)
	}
	// A missed invalidation is healed once the TTL expires.
	renamed := validTenant()
	renamed.Name = "renamed"
	look.set(fqdn, &renamed)
	clock.Advance(time.Second)
	got, err := r.Resolve(ctx, fqdn)
	if err != nil || got.Name != "renamed" || look.calls.Load() != 2 {
		t.Fatalf("expired entry served: %+v, %v", got, err)
	}

	// Positive caching disabled: every call reaches the lookup.
	look2 := newFakeLookup(validTenant())
	r2 := NewResolver(look2, WithPositiveTTL(0))
	for range 3 {
		if _, err := r2.Resolve(ctx, fqdn); err != nil {
			t.Fatal(err)
		}
	}
	if n := look2.calls.Load(); n != 3 || len(r2.positive) != 0 {
		t.Fatalf("positive cache used while disabled (%d calls)", n)
	}
	if DefaultPositiveTTL <= 0 || DefaultPositiveTTL > time.Hour {
		t.Fatalf("DefaultPositiveTTL = %v is not a bounded safety net", DefaultPositiveTTL)
	}
}

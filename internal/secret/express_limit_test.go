package secret

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// clockAt is a settable clock.
type clockAt struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clockAt) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clockAt) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// allow calls w.Allow and fails the test on a saturated answer.
func allow(t *testing.T, w *ExpressWindow, tid, client string, limit int) (bool, time.Duration) {
	t.Helper()
	ok, retry, saturated := w.Allow(tid, client, limit)
	if saturated {
		t.Fatalf("Allow(%s, %s) saturated", tid, client)
	}
	return ok, retry
}

func TestExpressWindowSliding(t *testing.T) {
	t.Parallel()
	clock := &clockAt{now: testNow}
	w := NewExpressWindow(time.Hour, 10, clock.Now)
	for i := range 3 {
		if ok, _ := allow(t, w, "a", "k", 3); !ok {
			t.Fatalf("event %d refused", i)
		}
		clock.advance(10 * time.Minute)
	}
	// At +30 min: the oldest event (at 0) leaves the window at +60 min.
	if ok, retry := allow(t, w, "a", "k", 3); ok || retry != 30*time.Minute {
		t.Fatalf("over the limit: %v, %v", ok, retry)
	}
	// Another client, or the same client on another tenant, is independent.
	if ok, _ := allow(t, w, "a", "other", 3); !ok {
		t.Fatal("other client refused")
	}
	if ok, _ := allow(t, w, "b", "k", 3); !ok {
		t.Fatal("same client on another tenant refused")
	}
	// A lower limit (the setting changed): the wait is until enough events
	// left the window; a limit below 1 counts as 1.
	if ok, retry := allow(t, w, "a", "k", 1); ok || retry != 50*time.Minute {
		t.Errorf("lower limit: %v, %v", ok, retry)
	}
	if ok, retry := allow(t, w, "a", "k", 0); ok || retry != 50*time.Minute {
		t.Errorf("zero limit: %v, %v", ok, retry)
	}
	clock.advance(30*time.Minute + time.Nanosecond)
	if ok, _ := allow(t, w, "a", "k", 3); !ok {
		t.Error("refused once the oldest event left the window")
	}
	if ok, retry := allow(t, w, "a", "k", 3); ok || retry != 10*time.Minute {
		t.Errorf("full again: %v, %v", ok, retry)
	}
	if w.Len() != 3 {
		t.Errorf("Len = %d", w.Len())
	}
}

func TestExpressWindowClamp(t *testing.T) {
	t.Parallel()
	clock := &clockAt{now: testNow}
	w := NewExpressWindow(time.Hour, 1, clock.Now)
	for i := range tenant.MaxExpressPerHourPerIP {
		if ok, _ := allow(t, w, "a", "k", 1<<20); !ok {
			t.Fatalf("event %d refused", i)
		}
	}
	if ok, retry := allow(t, w, "a", "k", 1<<20); ok || retry != time.Hour {
		t.Errorf("beyond the largest limit: %v, %v", ok, retry)
	}
}

// TestExpressWindowFull checks the bound of the clients of a tenant: a new
// client takes the place of a client without event in the window first,
// else of the least recently seen client below the limit; a table whose
// clients are all at their limit refuses a new client as saturated, until
// one of them drops below it, without affecting another tenant.
func TestExpressWindowFull(t *testing.T) {
	t.Parallel()
	clock := &clockAt{now: testNow}
	w := NewExpressWindow(time.Hour, 2, clock.Now)
	allow(t, w, "a", "x", 2)
	allow(t, w, "a", "y", 2)
	// Both below the limit of 2: "x", the least recently seen, goes.
	if ok, _ := allow(t, w, "a", "z", 2); !ok || w.Len() != 2 {
		t.Fatalf("new client on a table below its limit: %v, Len %d", ok, w.Len())
	}
	if ok, _ := allow(t, w, "a", "z", 2); !ok {
		t.Fatal("second event of z refused")
	}
	clock.advance(10 * time.Minute)
	allow(t, w, "a", "y", 2) // y at its limit too
	// Every client at its limit: a new client is refused as saturated,
	// until z (first event at 0) drops below the limit at +60 min.
	ok, retry, saturated := w.Allow("a", "x", 2)
	if ok || !saturated || retry != 50*time.Minute {
		t.Fatalf("new client on a saturated table: %v, %v, %v", ok, retry, saturated)
	}
	// A known client still counts, and another tenant is not affected.
	if ok, retry := allow(t, w, "a", "z", 2); ok || retry != 50*time.Minute {
		t.Errorf("known client at its limit: %v, %v", ok, retry)
	}
	if ok, _ := allow(t, w, "b", "x", 2); !ok {
		t.Error("another tenant refused")
	}
	// A client seen recently whose events all left the window goes first.
	clock.advance(50*time.Minute + time.Second) // +60:01: z holds none, y one
	if ok, _ := allow(t, w, "a", "x", 1); !ok {
		t.Fatal("new client refused while z has no event")
	}
	if ok, retry := allow(t, w, "a", "y", 1); ok || retry != 9*time.Minute+59*time.Second {
		t.Errorf("y kept: %v, %v", ok, retry)
	}
	// Every client idle for a period: forgotten, with their tenants.
	clock.advance(2 * time.Hour)
	if ok, _ := allow(t, w, "c", "k", 1); !ok || w.Len() != 1 {
		t.Errorf("after the window: %v, Len %d", ok, w.Len())
	}
}

// TestExpressWindowScanBound checks that only the expressEvictScan least
// recently seen clients are inspected: when they are all at their limit,
// a new client is refused even though a more recent one is below it.
func TestExpressWindowScanBound(t *testing.T) {
	t.Parallel()
	clock := &clockAt{now: testNow}
	w := NewExpressWindow(time.Hour, expressEvictScan+1, clock.Now)
	for i := range expressEvictScan {
		allow(t, w, "a", fmt.Sprint(i), 2)
		allow(t, w, "a", fmt.Sprint(i), 2)
	}
	allow(t, w, "a", "recent", 2)
	clock.advance(time.Minute)
	if ok, retry, saturated := w.Allow("a", "new", 2); ok || !saturated || retry != 59*time.Minute {
		t.Errorf("new client: %v, %v, %v", ok, retry, saturated)
	}
	if ok, _ := allow(t, w, "a", "recent", 2); !ok || w.Len() != expressEvictScan+1 {
		t.Errorf("the recent client below its limit: %v, Len %d", ok, w.Len())
	}
}

func TestNewExpressWindowDefaults(t *testing.T) {
	t.Parallel()
	w := NewExpressWindow(time.Hour, 0, nil)
	if w.maxKeys != 1 || w.clock == nil {
		t.Fatalf("window = %+v", w)
	}
	if ok, _ := allow(t, w, "a", "k", 1); !ok {
		t.Error("refused")
	}
}

func TestCeilSecond(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]time.Duration{
		-time.Second:            time.Second,
		0:                       time.Second,
		time.Nanosecond:         time.Second,
		1500 * time.Millisecond: 2 * time.Second,
		2 * time.Second:         2 * time.Second,
	} {
		if got := ceilSecond(d); got != want {
			t.Errorf("ceilSecond(%v) = %v, want %v", d, got, want)
		}
	}
}

// TestExpressWindowConcurrent counts concurrent events exactly.
func TestExpressWindowConcurrent(t *testing.T) {
	t.Parallel()
	w := NewExpressWindow(time.Hour, 100, nil)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for i := range 50 {
		wg.Go(func() {
			if allowed, _, _ := w.Allow("a", fmt.Sprint(i%2), 10); allowed {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 20 {
		t.Errorf("allowed %d, want 20", ok)
	}
}

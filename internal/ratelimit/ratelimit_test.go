package ratelimit

import (
	"math"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// fakeClock is a manually advanced, concurrency-safe clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
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

// step is one action of a scripted scenario.
type step struct {
	advance   time.Duration
	op        string // "allow", "fail", "locked", "reset"
	key       string
	wantOK    bool
	wantRetry time.Duration
}

func TestLimiterAllow(t *testing.T) {
	tests := []struct {
		name  string
		rate  rate.Limit
		burst int
		steps []step
	}{
		{
			name: "burst then refill", rate: 1, burst: 2,
			steps: []step{
				{key: "a", wantOK: true},
				{key: "a", wantOK: true},
				{key: "a", wantOK: false, wantRetry: time.Second},
				{advance: time.Second, key: "a", wantOK: true},
				{key: "a", wantOK: false, wantRetry: time.Second},
			},
		},
		{
			name: "retry after rounded up", rate: rate.Every(10 * time.Second), burst: 1,
			steps: []step{
				{key: "a", wantOK: true},
				{advance: 2500 * time.Millisecond, key: "a", wantOK: false, wantRetry: 8 * time.Second},
				{advance: 7500 * time.Millisecond, key: "a", wantOK: true},
			},
		},
		{
			name: "sub-second wait reported as one second", rate: 10, burst: 1,
			steps: []step{
				{key: "a", wantOK: true},
				{key: "a", wantOK: false, wantRetry: time.Second},
				{advance: 100 * time.Millisecond, key: "a", wantOK: true},
			},
		},
		{
			name: "keys are independent", rate: rate.Every(time.Hour), burst: 1,
			steps: []step{
				{key: "a", wantOK: true},
				{key: "b", wantOK: true},
				{key: "a", wantOK: false, wantRetry: time.Hour},
			},
		},
		{
			name: "infinite rate never limits", rate: rate.Inf, burst: 1,
			steps: []step{
				{key: "a", wantOK: true},
				{key: "a", wantOK: true},
				{key: "a", wantOK: true},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			l := New(tc.rate, tc.burst, WithClock(clk.Now))
			for i, s := range tc.steps {
				clk.Advance(s.advance)
				ok, retry := l.Allow(s.key)
				if ok != s.wantOK || retry != s.wantRetry {
					t.Fatalf("step %d: Allow(%q) = %v, %v; want %v, %v", i, s.key, ok, retry, s.wantOK, s.wantRetry)
				}
			}
		})
	}
}

func TestLimiterLRUEviction(t *testing.T) {
	clk := newFakeClock()
	l := New(rate.Every(time.Hour), 1, WithClock(clk.Now), WithMaxKeys(2))
	l.Allow("a")
	l.Allow("b")
	l.Allow("a") // a is now the most recently used; b is the eviction candidate
	l.Allow("c") // evicts b
	if got := l.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b should have been evicted and get a fresh bucket")
	}
	// Order was c, a (most recent first): re-adding b evicted a.
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a should have been evicted when b was re-added")
	}
}

func TestLimiterEvictionPrefersUnrestrictedBuckets(t *testing.T) {
	clk := newFakeClock()
	l := New(rate.Every(time.Minute), 2, WithClock(clk.Now), WithMaxKeys(2))
	l.Allow("y")
	l.Allow("y") // empty
	l.Allow("x") // one token left
	clk.Advance(time.Minute)
	// x is full again (lossless to forget), y holds one token: x is evicted
	// although y is the least recently used.
	l.Allow("z")
	if ok, _ := l.Allow("y"); !ok {
		t.Fatal("y should have one token")
	}
	if ok, _ := l.Allow("y"); ok {
		t.Fatal("y should have been kept and be empty now")
	}
	// Order is y, z (most recent first); z holds one token, y none: z goes.
	l.Allow("w")
	if ok, _ := l.Allow("y"); ok {
		t.Fatal("y should still be tracked and empty")
	}
}

func TestLimiterIdleTTL(t *testing.T) {
	tests := []struct {
		name     string
		opts     []Option
		advance  time.Duration
		wantKeys int
	}{
		{name: "default ttl keeps key before full refill", advance: 59 * time.Second, wantKeys: 1},
		{name: "default ttl evicts after full refill", advance: time.Minute, wantKeys: 0},
		{name: "custom ttl", opts: []Option{WithIdleTTL(10 * time.Second)}, advance: 10 * time.Second, wantKeys: 0},
		{name: "invalid options ignored", opts: []Option{WithIdleTTL(0), WithMaxKeys(0), WithClock(nil)}, advance: 30 * time.Second, wantKeys: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			opts := append([]Option{WithClock(clk.Now)}, tc.opts...)
			l := New(rate.Every(30*time.Second), 2, opts...) // full refill: 60 s
			l.Allow("a")
			clk.Advance(tc.advance)
			if got := l.Len(); got != tc.wantKeys {
				t.Fatalf("Len = %d, want %d", got, tc.wantKeys)
			}
		})
	}
}

func TestNewPanics(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
	}{
		{"zero rate", func() { New(0, 1) }},
		{"zero burst", func() { New(1, 0) }},
		{"zero limit", func() { NewWindow(0, time.Second) }},
		{"zero period", func() { NewWindow(1, 0) }},
		{"limit too large", func() { NewWindow(MaxWindowLimit+1, time.Second) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			tc.fn()
		})
	}
}

func TestFullRefill(t *testing.T) {
	tests := []struct {
		name  string
		rate  rate.Limit
		burst int
		want  time.Duration
	}{
		{"regular", 2, 10, 5 * time.Second},
		{"infinite rate", rate.Inf, 1, time.Nanosecond},
		{"overflow", rate.Limit(1e-12), math.MaxInt32, time.Duration(math.MaxInt64)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fullRefill(tc.rate, tc.burst); got != tc.want {
				t.Fatalf("fullRefill = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct {
		in, want time.Duration
	}{
		{0, time.Second},
		{time.Nanosecond, time.Second},
		{time.Second, time.Second},
		{time.Second + time.Nanosecond, 2 * time.Second},
		{90 * time.Second, 90 * time.Second},
	}
	for _, tc := range tests {
		if got := roundUp(tc.in); got != tc.want {
			t.Errorf("roundUp(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func runWindow(t *testing.T, clk *fakeClock, w *Window, steps []step) {
	t.Helper()
	for i, s := range steps {
		clk.Advance(s.advance)
		var ok bool
		var retry time.Duration
		switch s.op {
		case "allow":
			ok, retry = w.Allow(s.key)
		case "fail":
			ok, retry = w.Fail(s.key)
		case "locked":
			ok, retry = w.Locked(s.key)
		case "reset":
			w.Reset(s.key)
			continue
		default:
			t.Fatalf("unknown op %q", s.op)
		}
		if ok != s.wantOK || retry != s.wantRetry {
			t.Fatalf("step %d: %s(%q) = %v, %v; want %v, %v", i, s.op, s.key, ok, retry, s.wantOK, s.wantRetry)
		}
	}
}

func TestWindowAllow(t *testing.T) {
	tests := []struct {
		name   string
		limit  int
		period time.Duration
		steps  []step
	}{
		{
			name: "five codes per hour per address", limit: 5, period: time.Hour,
			steps: []step{
				{op: "allow", key: "a@example.com", wantOK: true},
				{op: "allow", key: "a@example.com", wantOK: true},
				{op: "allow", key: "a@example.com", wantOK: true},
				{op: "allow", key: "a@example.com", wantOK: true},
				{advance: 10 * time.Minute, op: "allow", key: "a@example.com", wantOK: true},
				{op: "allow", key: "a@example.com", wantOK: false, wantRetry: 50 * time.Minute},
				{op: "allow", key: "b@example.com", wantOK: true},
				{advance: 50 * time.Minute, op: "allow", key: "a@example.com", wantOK: true},
			},
		},
		{
			name: "retry after rounded up", limit: 1, period: time.Minute,
			steps: []step{
				{op: "allow", key: "ip", wantOK: true},
				{advance: 500 * time.Millisecond, op: "allow", key: "ip", wantOK: false, wantRetry: 60 * time.Second},
				{advance: 59 * time.Second, op: "allow", key: "ip", wantOK: false, wantRetry: time.Second},
				{advance: 500 * time.Millisecond, op: "allow", key: "ip", wantOK: true},
			},
		},
		{
			name: "no double burst across a window boundary", limit: 5, period: time.Hour,
			steps: []step{
				{advance: 59 * time.Minute, op: "allow", key: "a", wantOK: true},
				{op: "allow", key: "a", wantOK: true},
				{op: "allow", key: "a", wantOK: true},
				{op: "allow", key: "a", wantOK: true},
				{op: "allow", key: "a", wantOK: true},
				{advance: 2 * time.Minute, op: "allow", key: "a", wantOK: false, wantRetry: 58 * time.Minute},
				{advance: 57 * time.Minute, op: "allow", key: "a", wantOK: false, wantRetry: time.Minute},
				{advance: time.Minute, op: "allow", key: "a", wantOK: true},
				{op: "allow", key: "a", wantOK: true},
			},
		},
		{
			name: "events leave the window one by one", limit: 2, period: time.Hour,
			steps: []step{
				{op: "allow", key: "a", wantOK: true},
				{advance: 30 * time.Minute, op: "allow", key: "a", wantOK: true},
				{op: "allow", key: "a", wantOK: false, wantRetry: 30 * time.Minute},
				{advance: 30 * time.Minute, op: "allow", key: "a", wantOK: true},
				{op: "allow", key: "a", wantOK: false, wantRetry: 30 * time.Minute},
			},
		},
		{
			name: "allow refused while locked", limit: 1, period: time.Minute,
			steps: []step{
				{op: "fail", key: "k", wantOK: true, wantRetry: time.Minute},
				{op: "allow", key: "k", wantOK: false, wantRetry: time.Minute},
				{advance: time.Minute, op: "allow", key: "k", wantOK: true},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			runWindow(t, clk, NewWindow(tc.limit, tc.period, WithClock(clk.Now)), tc.steps)
		})
	}
}

func TestWindowLockout(t *testing.T) {
	tests := []struct {
		name  string
		opts  []Option
		steps []step
	}{
		{
			name: "three failures then fifteen minute lock",
			opts: []Option{WithLockout(15 * time.Minute)},
			steps: []step{
				{op: "locked", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{op: "locked", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: true, wantRetry: 15 * time.Minute},
				{advance: 5 * time.Minute, op: "locked", key: "t1", wantOK: true, wantRetry: 10 * time.Minute},
				{op: "fail", key: "t1", wantOK: true, wantRetry: 10 * time.Minute},
				{advance: 10 * time.Minute, op: "locked", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
			},
		},
		{
			name: "failures spread over windows do not lock",
			opts: []Option{WithLockout(15 * time.Minute)},
			steps: []step{
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{advance: 15 * time.Minute, op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: true, wantRetry: 15 * time.Minute},
			},
		},
		{
			name: "reset clears failures and lock",
			steps: []step{
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{op: "reset", key: "t1"},
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: true, wantRetry: 15 * time.Minute},
				{op: "reset", key: "t1"},
				{op: "locked", key: "t1", wantOK: false},
				{op: "reset", key: "unknown"},
			},
		},
		{
			name: "default lockout is the period",
			steps: []step{
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: true, wantRetry: 15 * time.Minute},
			},
		},
		{
			name: "invalid lockout ignored",
			opts: []Option{WithLockout(-time.Second)},
			steps: []step{
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: false},
				{op: "fail", key: "t1", wantOK: true, wantRetry: 15 * time.Minute},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			opts := append([]Option{WithClock(clk.Now)}, tc.opts...)
			runWindow(t, clk, NewWindow(3, 15*time.Minute, opts...), tc.steps)
		})
	}
}

func TestWindowMemoryBounds(t *testing.T) {
	t.Run("idle keys evicted before restricted ones", func(t *testing.T) {
		clk := newFakeClock()
		w := NewWindow(2, time.Hour, WithClock(clk.Now), WithMaxKeys(3))
		w.Allow("full")
		w.Allow("full") // at its limit: must be kept
		w.Allow("partial")
		w.Fail("locked")
		w.Fail("locked") // locked: must be kept
		w.Allow("d")     // evicts partial, the only evictable key
		if got := w.Len(); got != 3 {
			t.Fatalf("Len = %d, want 3", got)
		}
		if ok, _ := w.Allow("full"); ok {
			t.Fatal("full should still be limited")
		}
		if locked, _ := w.Locked("locked"); !locked {
			t.Fatal("lock must survive eviction")
		}
		if locked, _ := w.Locked("partial"); locked {
			t.Fatal("partial should have been evicted")
		}
	})
	t.Run("keys with expired events rank as idle", func(t *testing.T) {
		clk := newFakeClock()
		w := NewWindow(1, time.Minute, WithClock(clk.Now), WithMaxKeys(2), WithIdleTTL(time.Hour))
		w.Allow("old")
		clk.Advance(time.Minute) // old's event left the window
		w.Fail("locked")         // limit 1: locks immediately
		if ok, _ := w.Allow("new"); !ok {
			t.Fatal("old is idle and should have been evicted")
		}
		if locked, _ := w.Locked("locked"); !locked {
			t.Fatal("lock must survive")
		}
	})
	t.Run("full table of locked keys refuses new keys", func(t *testing.T) {
		clk := newFakeClock()
		w := NewWindow(1, 15*time.Minute, WithClock(clk.Now), WithMaxKeys(2))
		w.Fail("a")
		clk.Advance(time.Minute)
		w.Fail("b")
		clk.Advance(time.Minute)
		if ok, retry := w.Allow("c"); ok || retry != 13*time.Minute {
			t.Fatalf("Allow(c) = %v, %v; want false, 13m", ok, retry)
		}
		if locked, retry := w.Fail("c"); !locked || retry != 13*time.Minute {
			t.Fatalf("Fail(c) = %v, %v; want true, 13m", locked, retry)
		}
		if locked, _ := w.Locked("c"); locked {
			t.Fatal("refused key must not be tracked")
		}
		if got := w.Len(); got != 2 {
			t.Fatalf("Len = %d, want 2", got)
		}
		clk.Advance(13 * time.Minute) // a's lock ended and a expired
		if ok, _ := w.Allow("c"); !ok {
			t.Fatal("c should be admitted once a slot frees up")
		}
		if locked, _ := w.Locked("b"); !locked {
			t.Fatal("b must still be locked")
		}
	})
	t.Run("churn of many keys cannot clear a lock", func(t *testing.T) {
		clk := newFakeClock()
		w := NewWindow(3, 15*time.Minute, WithClock(clk.Now), WithMaxKeys(100))
		for range 3 {
			w.Fail("victim")
		}
		for i := range 10_000 {
			w.Fail("2001:db8:" + strconv.Itoa(i) + "::1")
			clk.Advance(time.Millisecond)
		}
		if locked, _ := w.Locked("victim"); !locked {
			t.Fatal("churn cleared the lock")
		}
		if got := w.Len(); got > 100 {
			t.Fatalf("Len = %d, bound exceeded", got)
		}
	})
	t.Run("eviction scan is bounded", func(t *testing.T) {
		clk := newFakeClock()
		w := NewWindow(2, time.Hour, WithClock(clk.Now), WithMaxKeys(maxEvictScan+1))
		for i := range maxEvictScan {
			key := "k" + strconv.Itoa(i)
			w.Allow(key)
			w.Allow(key) // at its limit
		}
		w.Allow("evictable") // below its limit, but newer than the scanned keys
		if ok, _ := w.Allow("new"); ok {
			t.Fatal("keys beyond the scan bound must not be inspected")
		}
	})
	t.Run("default idle ttl covers lockout", func(t *testing.T) {
		clk := newFakeClock()
		w := NewWindow(1, time.Minute, WithClock(clk.Now), WithLockout(time.Hour))
		w.Fail("a")
		clk.Advance(59 * time.Minute)
		if locked, _ := w.Locked("a"); !locked {
			t.Fatal("lock must survive until it ends")
		}
		clk.Advance(time.Minute)
		if got := w.Len(); got != 0 {
			t.Fatalf("Len = %d, want 0 after lockout", got)
		}
	})
	t.Run("short idle ttl cannot drop a lock or an event", func(t *testing.T) {
		clk := newFakeClock()
		w := NewWindow(1, time.Hour, WithClock(clk.Now), WithIdleTTL(time.Minute), WithLockout(2*time.Hour))
		w.Allow("a")
		w.Fail("b")
		clk.Advance(time.Minute)
		if ok, _ := w.Allow("a"); ok {
			t.Fatal("event of a forgotten after the idle TTL")
		}
		if locked, _ := w.Locked("b"); !locked {
			t.Fatal("lock of b dropped after the idle TTL")
		}
		clk.Advance(2 * time.Hour)
		if got := w.Len(); got != 0 {
			t.Fatalf("Len = %d, want 0 once the lock ended", got)
		}
	})
}

func TestConcurrentUse(t *testing.T) {
	l := New(rate.Every(time.Hour), 100, WithMaxKeys(16))
	w := NewWindow(100, time.Hour, WithMaxKeys(16))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 1000 {
				key := strconv.Itoa((g + i) % 32)
				l.Allow(key)
				w.Allow(key)
				w.Fail(key)
				w.Locked(key)
				if i%100 == 0 {
					w.Reset(key)
				}
			}
		})
	}
	wg.Wait()
	if l.Len() > 16 || w.Len() > 16 {
		t.Fatalf("bounds exceeded: limiter %d, window %d", l.Len(), w.Len())
	}
}

func BenchmarkLimiterAllow(b *testing.B) {
	l := New(1000, 100)
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = "198.51.100." + strconv.Itoa(i)
	}
	b.ResetTimer()
	for i := range b.N {
		l.Allow(keys[i%len(keys)])
	}
}

func BenchmarkWindowAllow(b *testing.B) {
	w := NewWindow(20, time.Hour)
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = "198.51.100." + strconv.Itoa(i)
	}
	b.ResetTimer()
	for i := range b.N {
		w.Allow(keys[i%len(keys)])
	}
}

func TestWindowRefund(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(2, time.Minute, WithClock(clk.Now))
	w.Refund("unknown") // nothing counted: no effect, no panic
	for range 2 {
		if ok, _ := w.Allow("k"); !ok {
			t.Fatal("refused below the limit")
		}
	}
	if ok, _ := w.Allow("k"); ok {
		t.Fatal("allowed above the limit")
	}
	w.Refund("k")
	if ok, _ := w.Allow("k"); !ok {
		t.Fatal("refunded slot not available")
	}
	// Events that left the window are not refunded twice.
	clk.Advance(time.Minute)
	w.Refund("k")
	for range 2 {
		if ok, _ := w.Allow("k"); !ok {
			t.Fatal("refused after the window")
		}
	}
}

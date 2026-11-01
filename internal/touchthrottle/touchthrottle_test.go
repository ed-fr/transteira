package touchthrottle

import (
	"sync"
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	d := New(0, -1)
	if d.Interval() != DefaultInterval || d.MaxTracked() != DefaultMaxTracked || d.Len() != 0 {
		t.Errorf("defaults: %v %d %d", d.Interval(), d.MaxTracked(), d.Len())
	}
	c := New(time.Second, 3)
	if c.Interval() != time.Second || c.MaxTracked() != 3 {
		t.Errorf("custom: %v %d", c.Interval(), c.MaxTracked())
	}
}

func TestDue(t *testing.T) {
	t.Parallel()
	th := New(time.Minute, 2)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !th.Due("a", t0) || th.Due("a", t0.Add(59*time.Second)) || !th.Due("a", t0.Add(time.Minute)) {
		t.Fatal("interval not applied")
	}
	// A clock going backwards records again.
	if !th.Due("a", t0) {
		t.Fatal("backwards clock not recorded")
	}
	// Full memory: the stale entry ("a", at t0) is dropped, the fresh one kept.
	if !th.Due("b", t0.Add(90*time.Second)) || th.Len() != 2 {
		t.Fatalf("len = %d", th.Len())
	}
	if !th.Due("c", t0.Add(2*time.Minute)) || th.Len() != 2 || th.Tracked("a") || !th.Tracked("b") {
		t.Fatalf("stale entry not dropped: len %d", th.Len())
	}
	// Full memory of fresh entries: everything is cleared.
	if !th.Due("d", t0.Add(2*time.Minute)) || th.Len() != 1 || !th.Tracked("d") {
		t.Fatalf("memory not cleared: len %d", th.Len())
	}
	// A known key never triggers the eviction.
	if th.Due("d", t0.Add(2*time.Minute+time.Second)) {
		t.Error("known key recorded within the interval")
	}
	th.Forget("d")
	if th.Tracked("d") || th.Len() != 0 {
		t.Error("forget kept the key")
	}
	th.Forget("unknown")
}

func TestConcurrent(t *testing.T) {
	t.Parallel()
	th := New(time.Hour, 10)
	now := time.Now()
	var wg sync.WaitGroup
	recorded := make(chan bool, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorded <- th.Due("k", now)
		}()
	}
	wg.Wait()
	close(recorded)
	n := 0
	for r := range recorded {
		if r {
			n++
		}
	}
	if n != 1 {
		t.Errorf("recorded %d times, want 1", n)
	}
}

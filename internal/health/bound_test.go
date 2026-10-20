package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func counting(n *atomic.Int32) Checker {
	return CheckerFunc(func(context.Context) error { n.Add(1); return nil })
}

func TestRunCachesReport(t *testing.T) {
	var calls atomic.Int32
	clk := newClock()
	svc := &Service{
		Database:  Check{Checker: counting(&calls)},
		Antivirus: Check{Checker: ok},
		Storage:   Check{Checker: ok},
		now:       clk.now,
	}
	for range 3 {
		if r := svc.Run(context.Background()); !r.Healthy() {
			t.Fatalf("Run = %+v", r)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("checks ran %d times within the TTL, want 1", n)
	}
	clk.advance(CacheTTL - time.Nanosecond)
	svc.Run(context.Background())
	if n := calls.Load(); n != 1 {
		t.Fatalf("checks ran %d times just before expiry, want 1", n)
	}
	clk.advance(time.Nanosecond)
	svc.Run(context.Background())
	if n := calls.Load(); n != 2 {
		t.Fatalf("checks ran %d times after expiry, want 2", n)
	}
}

func TestRunSharesInFlight(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	slow := CheckerFunc(func(context.Context) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	})
	svc := &Service{
		Database:  Check{Checker: slow, Timeout: 10 * time.Second},
		Antivirus: Check{Checker: ok},
		Storage:   Check{Checker: ok},
		now:       newClock().now, // frozen: late callers hit the cache
	}

	const callers = 20
	reports := make(chan Report, callers)
	var wg sync.WaitGroup
	wg.Go(func() { reports <- svc.Run(context.Background()) })
	<-started
	for range callers - 1 {
		wg.Go(func() { reports <- svc.Run(context.Background()) })
	}
	close(release)
	wg.Wait()
	close(reports)
	for r := range reports {
		if !r.Healthy() {
			t.Fatalf("Run = %+v", r)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("checks ran %d times for concurrent callers, want 1", n)
	}
}

func TestRunCallerCancellationDoesNotCancelSharedRun(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var checkErr atomic.Value
	slow := CheckerFunc(func(ctx context.Context) error {
		close(started)
		<-release
		checkErr.Store(errors.Join(ctx.Err(), errors.New("observed")))
		return ctx.Err()
	})
	svc := &Service{
		Database:  Check{Checker: slow, Timeout: 10 * time.Second},
		Antivirus: Check{Checker: ok},
		Storage:   Check{Checker: ok},
		now:       newClock().now,
	}

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan Report, 1)
	go func() { first <- svc.Run(ctx) }()
	<-started
	second := make(chan Report, 1)
	go func() { second <- svc.Run(context.Background()) }()

	cancel()
	if r := <-first; r != unavailableReport {
		t.Fatalf("canceled caller got %+v, want all unavailable", r)
	}
	close(release)
	if r := <-second; !r.Healthy() {
		t.Fatalf("other caller got %+v; the shared run was canceled", r)
	}
	if err := checkErr.Load().(error); err.Error() != "observed" {
		t.Fatalf("check context error = %v", err)
	}
}

// hangRemove makes the storage probe block in removeFile until release is
// closed, simulating a hung disk.
func hangRemove(t *testing.T) (entered <-chan struct{}, release chan struct{}) {
	t.Helper()
	orig := removeFile
	in := make(chan struct{}, 16)
	release = make(chan struct{})
	removeFile = func(name string) error {
		in <- struct{}{}
		<-release
		return orig(name)
	}
	t.Cleanup(func() { removeFile = orig })
	return in, release
}

func TestStorageCheckSkipsWhileProbeRunning(t *testing.T) {
	entered, release := hangRemove(t)
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	check := StorageCheck(t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := check.Check(ctx); err == nil || !strings.Contains(err.Error(), "abandoned") {
		t.Fatalf("hung probe = %v, want abandoned", err)
	}
	<-entered

	for range 5 {
		if err := check.Check(context.Background()); !errors.Is(err, errProbeRunning) {
			t.Fatalf("Check while probe hung = %v, want %v", err, errProbeRunning)
		}
	}
	if n := len(entered); n != 0 {
		t.Fatalf("%d extra probes started while one was hung", n)
	}

	close(release)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := check.Check(context.Background())
		if err == nil {
			break
		}
		if !errors.Is(err, errProbeRunning) || time.Now().After(deadline) {
			t.Fatalf("Check after release = %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHandlerHungStorageHidesDetails(t *testing.T) {
	entered, release := hangRemove(t)
	t.Cleanup(func() { close(release) })
	storage := StorageCheck(t.TempDir())
	clk := newClock()
	svc := &Service{
		Database:  Check{Checker: ok},
		Antivirus: Check{Checker: ok},
		Storage:   Check{Checker: storage, Timeout: 20 * time.Millisecond},
		now:       clk.now,
	}
	h := Handler(svc, nil)
	for i := range 2 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		body := rec.Body.String()
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(body, `"storage":"unavailable"`) {
			t.Fatalf("run %d = %d %s", i, rec.Code, body)
		}
		for _, leak := range []string{"probe", "abandoned", "running", "health:"} {
			if strings.Contains(body, leak) {
				t.Fatalf("run %d body leaks %q: %s", i, leak, body)
			}
		}
		if i == 0 {
			<-entered
		}
		clk.advance(CacheTTL)
	}
}

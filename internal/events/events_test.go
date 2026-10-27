package events

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newTestBus returns a bus logging to the returned buffer, with clock now.
func newTestBus(now func() time.Time) (*Bus, *syncBuffer) {
	logs := &syncBuffer{}
	return New(Options{Now: now, Logger: slog.New(slog.NewTextHandler(logs, nil))}), logs
}

// collector is a handler keeping the events it receives.
type collector struct {
	mu     sync.Mutex
	events []Event
}

func (c *collector) handle(_ context.Context, ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *collector) got() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.events...)
}

func closeBus(t *testing.T, b *Bus) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	if b.warnInterval != DefaultWarnInterval || b.now == nil || b.logger == nil {
		t.Fatalf("defaults not applied: %+v", b)
	}
}

func TestDiscardAndOrDiscard(t *testing.T) {
	t.Parallel()
	Discard.Publish(Event{Type: LogAudit}) // must not panic
	if OrDiscard(nil) != Discard {
		t.Fatal("OrDiscard(nil) is not Discard")
	}
	r := &Recorder{}
	if OrDiscard(r) != r {
		t.Fatal("OrDiscard(p) is not p")
	}
	var nilBus *Bus
	nilBus.Publish(Event{Type: LogAudit}) // no-op on a nil bus
	if nilBus.Dropped("x") != 0 {
		t.Fatal("Dropped on a nil bus")
	}
}

func TestAdminPathTenantAudit(t *testing.T) {
	t.Parallel()
	if got := AdminPathTenantAudit("ten_1"); got != "/admin/tenants/ten_1/audit" {
		t.Fatalf("AdminPathTenantAudit = %q", got)
	}
}

func TestRecorder(t *testing.T) {
	t.Parallel()
	r := &Recorder{}
	r.Publish(Event{Type: QuotaWarning})
	r.Publish(Event{Type: QuotaReached})
	r.Publish(Event{Type: QuotaWarning, TenantID: "x"})
	if got := r.Events(); len(got) != 3 {
		t.Fatalf("Events = %d, want 3", len(got))
	}
	if got := r.OfType(QuotaWarning); len(got) != 2 || got[1].TenantID != "x" {
		t.Fatalf("OfType = %+v", got)
	}
	if got := r.OfType(DiskAlertRaised); got != nil {
		t.Fatalf("OfType(none) = %+v", got)
	}
}

func TestSubscribeValidation(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	h := func(context.Context, Event) {}
	if err := b.Subscribe("", nil, 0, h); !errors.Is(err, ErrInvalidSubscriber) {
		t.Fatalf("empty name: %v", err)
	}
	if err := b.Subscribe("a", nil, 0, nil); !errors.Is(err, ErrInvalidSubscriber) {
		t.Fatalf("nil handler: %v", err)
	}
	if err := b.Subscribe("a", nil, 0, h); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if cap(b.byName["a"].queue) != DefaultBuffer {
		t.Fatalf("default buffer = %d", cap(b.byName["a"].queue))
	}
	if err := b.Subscribe("a", nil, 1, h); !errors.Is(err, ErrInvalidSubscriber) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := b.Start(context.Background()); !errors.Is(err, ErrStarted) {
		t.Fatalf("second Start: %v", err)
	}
	if err := b.Subscribe("b", nil, 1, h); !errors.Is(err, ErrStarted) {
		t.Fatalf("Subscribe after Start: %v", err)
	}
	closeBus(t, b)
	if err := b.Subscribe("c", nil, 1, h); !errors.Is(err, ErrClosed) {
		t.Fatalf("Subscribe after Close: %v", err)
	}
	if err := b.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close: %v", err)
	}
	closeBus(t, b) // a second Close is harmless
}

func TestPublishOrderFilterAndDefaults(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	b, _ := newTestBus(func() time.Time { return at })
	all, alerts := &collector{}, &collector{}
	if err := b.Subscribe("all", nil, 100, all.handle); err != nil {
		t.Fatal(err)
	}
	onlyQuota := func(tp Type) bool { return tp == QuotaWarning || tp == QuotaReached }
	if err := b.Subscribe("quota", onlyQuota, 100, alerts.handle); err != nil {
		t.Fatal(err)
	}
	// Published before Start: kept in the queues.
	b.Publish(Event{Type: QuotaWarning})
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	given := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	b.Publish(Event{Type: LogAudit, ID: "evt_given", OccurredAt: given})
	for range 50 {
		b.Publish(Event{Type: QuotaReached})
	}
	closeBus(t, b)
	got := all.got()
	if len(got) != 52 {
		t.Fatalf("all received %d events, want 52", len(got))
	}
	if got[0].Type != QuotaWarning || !id.Valid(id.Event, got[0].ID) || !got[0].OccurredAt.Equal(at) {
		t.Fatalf("first event = %+v", got[0])
	}
	if got[1].ID != "evt_given" || !got[1].OccurredAt.Equal(given) {
		t.Fatalf("given ID and time overwritten: %+v", got[1])
	}
	seen := map[string]bool{}
	for i, ev := range got[2:] {
		if ev.Type != QuotaReached || seen[ev.ID] {
			t.Fatalf("event %d = %+v (duplicate ID: %v)", i+2, ev, seen[ev.ID])
		}
		seen[ev.ID] = true
	}
	q := alerts.got()
	if len(q) != 51 || q[0].Type != QuotaWarning {
		t.Fatalf("filtered subscriber received %d events", len(q))
	}
	// Published once closed: dropped silently.
	b.Publish(Event{Type: QuotaReached})
	if len(all.got()) != 52 || b.Dropped("all") != 0 {
		t.Fatal("an event published after Close was delivered or counted")
	}
}

func TestFullQueueDropsAndWarnsRateLimited(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	b, logs := newTestBus(clock)
	release := make(chan struct{})
	slow, fast := &collector{}, &collector{}
	entered := make(chan struct{}, 1)
	err := b.Subscribe("slow", nil, 2, func(ctx context.Context, ev Event) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		slow.handle(ctx, ev)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Subscribe("fast", nil, 100, fast.handle); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Publish(Event{Type: LogAudit}) // taken by the slow handler
	<-entered
	b.Publish(Event{Type: LogAudit}) // queued (1/2)
	b.Publish(Event{Type: LogAudit}) // queued (2/2)
	b.Publish(Event{Type: LogAudit}) // dropped, warned
	b.Publish(Event{Type: LogAudit}) // dropped, not warned (interval)
	if n := strings.Count(logs.String(), "subscriber queue full"); n != 1 {
		t.Fatalf("%d warnings, want 1:\n%s", n, logs.String())
	}
	mu.Lock()
	now = now.Add(DefaultWarnInterval)
	mu.Unlock()
	b.Publish(Event{Type: LogAudit}) // dropped, warned again with 2 since
	if n := strings.Count(logs.String(), "subscriber queue full"); n != 2 {
		t.Fatalf("%d warnings, want 2:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "dropped=2 dropped_total=3") {
		t.Fatalf("second warning lacks the counts:\n%s", logs.String())
	}
	if b.Dropped("slow") != 3 || b.Dropped("fast") != 0 || b.Dropped("unknown") != 0 {
		t.Fatalf("Dropped: slow=%d fast=%d", b.Dropped("slow"), b.Dropped("fast"))
	}
	close(release)
	closeBus(t, b)
	if len(slow.got()) != 3 || len(fast.got()) != 6 {
		t.Fatalf("delivered slow=%d fast=%d, want 3 and 6", len(slow.got()), len(fast.got()))
	}
}

func TestCloseDrainsTheQueues(t *testing.T) {
	t.Parallel()
	b, _ := newTestBus(nil)
	c := &collector{}
	gate := make(chan struct{})
	err := b.Subscribe("s", nil, 10, func(ctx context.Context, ev Event) {
		<-gate
		c.handle(ctx, ev)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		b.Publish(Event{Type: DiskAlertRaised})
	}
	go close(gate)
	closeBus(t, b)
	if len(c.got()) != 5 {
		t.Fatalf("Close delivered %d events, want 5", len(c.got()))
	}
}

func TestCloseDeadlineCancelsAndDiscards(t *testing.T) {
	t.Parallel()
	b, _ := newTestBus(nil)
	var calls sync.WaitGroup
	calls.Add(1)
	gate := make(chan struct{})
	handled := 0
	var mu sync.Mutex
	err := b.Subscribe("s", nil, 10, func(ctx context.Context, _ Event) {
		mu.Lock()
		handled++
		first := handled == 1
		mu.Unlock()
		if first {
			calls.Done()
			<-ctx.Done() // canceled when the Close deadline passes
			<-gate
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		b.Publish(Event{Type: DiskAlertRaised})
	}
	calls.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v, want deadline exceeded", err)
	}
	close(gate)
	<-b.done
	mu.Lock()
	defer mu.Unlock()
	if handled != 1 {
		t.Fatalf("handler called %d times after the deadline, want only the first", handled)
	}
}

func TestCloseBeforeStart(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	if err := b.Subscribe("s", nil, 1, func(context.Context, Event) {}); err != nil {
		t.Fatal(err)
	}
	b.Publish(Event{Type: LogSecurity})
	closeBus(t, b)
}

func TestHandlerPanicIsRecovered(t *testing.T) {
	t.Parallel()
	b, logs := newTestBus(nil)
	c := &collector{}
	err := b.Subscribe("s", nil, 10, func(ctx context.Context, ev Event) {
		if ev.Type == VirusDetected {
			panic("boom")
		}
		c.handle(ctx, ev)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Publish(Event{Type: VirusDetected})
	b.Publish(Event{Type: QuotaWarning})
	closeBus(t, b)
	if got := c.got(); len(got) != 1 || got[0].Type != QuotaWarning {
		t.Fatalf("events after the panic = %+v", got)
	}
	if !strings.Contains(logs.String(), "subscriber panicked") || !strings.Contains(logs.String(), "boom") {
		t.Fatalf("panic not logged:\n%s", logs.String())
	}
}

func TestStartContextCancellationDoesNotStop(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	c := &collector{}
	if err := b.Subscribe("s", nil, 10, c.handle); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	b.Publish(Event{Type: MaintenanceEnabled})
	closeBus(t, b)
	if len(c.got()) != 1 {
		t.Fatal("the cancellation of the Start context stopped the delivery")
	}
}

func TestConcurrentPublishAndClose(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	if err := b.Subscribe("s", nil, 4, func(context.Context, Event) {}); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				b.Publish(Event{Type: LogAudit})
			}
		})
	}
	closeBus(t, b)
	wg.Wait()
}

func TestFilterPanicIsRecovered(t *testing.T) {
	t.Parallel()
	b, logs := newTestBus(nil)
	good := &collector{}
	err := b.Subscribe("bad", func(Type) bool { panic("filter boom") }, 10, func(context.Context, Event) {
		t.Error("the handler of a panicking filter was called")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Subscribe("good", nil, 10, good.handle); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Publish(Event{Type: QuotaWarning})
	b.Publish(Event{Type: QuotaReached})
	closeBus(t, b)
	if len(good.got()) != 2 || b.Dropped("bad") != 2 || b.Dropped("good") != 0 {
		t.Fatalf("good=%d dropped(bad)=%d", len(good.got()), b.Dropped("bad"))
	}
	if n := strings.Count(logs.String(), "subscriber filter panicked"); n != 1 {
		t.Fatalf("%d filter panic warnings, want 1 (rate limited): %s", n, logs.String())
	}
}

func TestPublishDefaultsCounts(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	c := &collector{}
	if err := b.Subscribe("s", nil, 10, c.handle); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Publish(Event{Type: MaintenanceEnabled})
	b.Publish(Event{Type: QuotaWarning, Counts: map[string]float64{"usedRatio": 0.8}})
	closeBus(t, b)
	got := c.got()
	if len(got) != 2 || got[0].Counts == nil || len(got[0].Counts) != 0 || got[1].Counts["usedRatio"] != 0.8 {
		t.Fatalf("counts = %+v", got)
	}
}

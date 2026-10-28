package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
)

// recordCall is a call of fakeStore.RecordDelivery.
type recordCall struct {
	tenantID, id string
	d            Delivery
}

// fakeStore serves the targets of each owner and keeps the calls.
type fakeStore struct {
	mu      sync.Mutex
	targets map[string][]Target
	queried []string
	records []recordCall
	subErr  error
	recErr  error
	// targetErr fails Target.
	targetErr error
	// onTarget, when set, runs before the n-th call of Target (1-based),
	// with the lock held, to change the targets.
	onTarget func(s *fakeStore, n int)
	// targetCalls counts the calls of Target.
	targetCalls int
	// answer, when set, replaces the target answered by Target.
	answer func(t Target) Target
}

func (s *fakeStore) Target(_ context.Context, tenantID, id string) (Target, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetCalls++
	if s.onTarget != nil {
		s.onTarget(s, s.targetCalls)
	}
	if s.targetErr != nil {
		return Target{}, false, s.targetErr
	}
	for _, t := range s.targets[tenantID] {
		if t.ID == id {
			if s.answer != nil {
				t = s.answer(t)
			}
			return t, true, nil
		}
	}
	return Target{}, false, nil
}

// set replaces the targets of tenantID.
func (s *fakeStore) set(tenantID string, list ...Target) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets[tenantID] = list
}

func (s *fakeStore) Subscribers(_ context.Context, tenantID string, _ events.Type) ([]Ref, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queried = append(s.queried, tenantID)
	if s.subErr != nil {
		return nil, s.subErr
	}
	refs := make([]Ref, 0, len(s.targets[tenantID]))
	for _, t := range s.targets[tenantID] {
		refs = append(refs, Ref{ID: t.ID, TenantID: t.TenantID, CircuitOpenUntil: t.CircuitOpenUntil})
	}
	return refs, nil
}

func (s *fakeStore) RecordDelivery(_ context.Context, tenantID, id string, d Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, recordCall{tenantID, id, d})
	return s.recErr
}

func (s *fakeStore) snapshot() ([]string, []recordCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.queried), slices.Clone(s.records)
}

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

// eventually waits until cond holds, failing after 10 s.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitIdle waits until store holds n records and d has no worker left.
func waitIdle(t *testing.T, d *Dispatcher, store *fakeStore, n int) []recordCall {
	t.Helper()
	eventually(t, "idle dispatcher", func() bool {
		_, records := store.snapshot()
		d.mu.Lock()
		defer d.mu.Unlock()
		return len(records) == n && len(d.queues) == 0
	})
	_, records := store.snapshot()
	return records
}

// fixedNow is the clock of the dispatcher tests.
var fixedNow = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

func newTestDispatcher(t *testing.T, store *fakeStore, c *Client, mod func(*DispatcherOptions)) (*Dispatcher, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	opts := DispatcherOptions{
		Store: store, Client: c, Logger: slog.New(slog.NewTextHandler(logs, nil)),
		Now: func() time.Time { return fixedNow }, Backoff: func(int) time.Duration { return time.Millisecond },
	}
	if mod != nil {
		mod(&opts)
	}
	d, err := NewDispatcher(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close(context.Background()) })
	return d, logs
}

func tenantEvent(tenantID string) events.Event {
	ev := testEvent()
	ev.TenantID = tenantID
	return ev
}

func TestNewDispatcher(t *testing.T) {
	c := testClient(t, nil, nil)
	if _, err := NewDispatcher(DispatcherOptions{Client: c}); err == nil {
		t.Error("no store accepted")
	}
	if _, err := NewDispatcher(DispatcherOptions{Store: &fakeStore{}}); err == nil {
		t.Error("no client accepted")
	}
	d, err := NewDispatcher(DispatcherOptions{Store: &fakeStore{}, Client: c})
	if err != nil {
		t.Fatal(err)
	}
	if d.queueSize != DefaultQueueSize || d.parallelism != DefaultTenantParallelism ||
		d.warnInterval != DefaultWarnInterval || d.now == nil || d.logger == nil {
		t.Errorf("defaults %+v", d)
	}
	if d.backoff(1) != time.Second || d.backoff(2) != 2*time.Second || d.backoff(20) != 5*time.Minute {
		t.Error("default backoff")
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDispatcherThroughBus(t *testing.T) {
	r := newReceiver(t)
	tg := genericTarget(r)
	store := &fakeStore{targets: map[string][]Target{"ten_a": {tg}}}
	d, _ := newTestDispatcher(t, store, testClient(t, r, nil), nil)
	bus := events.New(events.Options{})
	if err := d.Register(bus); err != nil {
		t.Fatal(err)
	}
	if err := d.Register(bus); err == nil {
		t.Error("registered twice")
	}
	if err := bus.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus.Publish(tenantEvent("ten_a"))
	bus.Publish(events.Event{Type: events.LogAudit, TenantID: "ten_a"}) // not subscribable
	bus.Publish(events.Event{Type: events.WebhookTest, TenantID: "ten_a"})
	waitIdle(t, d, store, 1)
	if err := bus.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	queried, records := store.snapshot()
	if !slices.Equal(queried, []string{"ten_a"}) || len(records) != 1 || records[0].id != "whk_1" ||
		records[0].tenantID != "ten_a" || !records[0].d.Result.Success || records[0].d.ConsecutiveFailures != 0 ||
		!records[0].d.At.Equal(fixedNow) || !records[0].d.Version.Equal(tg.Version) {
		t.Errorf("queried %v, records %+v", queried, records)
	}
	if err := verifySignature(r.reqs[0].Header.Get(HeaderSignature), tg.Secret, r.body[0], time.Now()); err != nil {
		t.Errorf("signature: %v", err)
	}
}

func TestDispatcherRouting(t *testing.T) {
	r := newReceiver(t)
	a, b, sys := genericTarget(r), genericTarget(r), genericTarget(r)
	b.ID, b.TenantID = "whk_b", "ten_b"
	sys.ID, sys.TenantID, sys.TenantName = "whk_sys", "", ""
	foreign := genericTarget(r)
	foreign.ID, foreign.TenantID = "whk_foreign", "ten_b"
	store := &fakeStore{targets: map[string][]Target{
		"ten_a": {a, foreign}, "ten_b": {b}, "": {sys},
	}}
	d, logs := newTestDispatcher(t, store, testClient(t, r, nil), nil)
	ctx := context.Background()

	// A tenant event only reads the webhooks of its tenant; a webhook of
	// another owner returned by the store is ignored.
	d.Handle(ctx, tenantEvent("ten_a"))
	// A system event only reads the system webhooks, whatever its tenant.
	sysEv := events.Event{
		ID: "evt_s", Type: events.DiskAlertRaised, Severity: events.SeverityWarning,
		OccurredAt: fixedNow, TenantID: "ten_a", Counts: map[string]float64{"usedRatio": 0.9},
	}
	d.Handle(ctx, sysEv)
	// A tenant event without tenant is dropped without any read.
	d.Handle(ctx, tenantEvent(""))
	// Other types are ignored.
	d.Handle(ctx, events.Event{Type: events.WebhookTest, TenantID: "ten_a"})
	d.Handle(ctx, events.Event{Type: events.LogSecurity})

	waitIdle(t, d, store, 2)
	queried, records := store.snapshot()
	if !slices.Equal(queried, []string{"ten_a", ""}) {
		t.Errorf("queried %v", queried)
	}
	got := map[string]string{}
	for _, rec := range records {
		got[rec.id] = rec.tenantID
	}
	if len(got) != 2 || got["whk_1"] != "ten_a" || got["whk_sys"] != "" {
		t.Errorf("records %v", got)
	}
	if d.Dropped() != 2 {
		t.Errorf("dropped %d", d.Dropped())
	}
	// The system webhook received no tenant and no address.
	for i, req := range r.reqs {
		if req.Header.Get(HeaderEvent) == string(events.DiskAlertRaised) &&
			(strings.Contains(string(r.body[i]), "tenant") || strings.Contains(string(r.body[i]), "@")) {
			t.Errorf("system payload %s", r.body[i])
		}
	}
	if s := logs.String(); !strings.Contains(s, "whk_foreign") || strings.Contains(s, "secret-part") ||
		strings.Contains(s, "example.com:") {
		t.Errorf("logs %s", s)
	}
}

func TestDispatcherRetriesAndBreaker(t *testing.T) {
	r := newReceiver(t)
	r.status = func(n int) int {
		if n <= 2 {
			return http.StatusBadGateway
		}
		return http.StatusOK
	}
	tg := genericTarget(r)
	store := &fakeStore{targets: map[string][]Target{"ten_a": {tg}}}
	var backoffs []int
	var mu sync.Mutex
	d, logs := newTestDispatcher(t, store, testClient(t, r, nil), func(o *DispatcherOptions) {
		o.Backoff = func(n int) time.Duration {
			mu.Lock()
			backoffs = append(backoffs, n)
			mu.Unlock()
			return time.Millisecond
		}
	})
	d.Handle(context.Background(), tenantEvent("ten_a"))
	waitIdle(t, d, store, 1)
	if r.count() != 3 || !slices.Equal(backoffs, []int{1, 2}) {
		t.Errorf("attempts %d, backoffs %v", r.count(), backoffs)
	}
	// Every attempt carries the same delivery ID.
	for _, req := range r.reqs {
		if req.Header.Get(HeaderDelivery) != "evt_1" {
			t.Errorf("delivery header %q", req.Header.Get(HeaderDelivery))
		}
	}

	// Five failed attempts: one failed delivery; the fifth failed
	// delivery in a row opens the circuit.
	r.status = func(int) int { return http.StatusInternalServerError }
	tg.ConsecutiveFailures = BreakerThreshold - 1
	store.set("ten_a", tg)
	before := r.count()
	d.Handle(context.Background(), tenantEvent("ten_a"))
	records := waitIdle(t, d, store, 2)
	last := records[len(records)-1].d
	if r.count()-before != MaxAttempts || last.Result.Success || last.Result.Category != CategoryHTTPStatus ||
		last.Result.HTTPStatus != 500 || last.ConsecutiveFailures != BreakerThreshold ||
		!last.CircuitOpenUntil.Equal(fixedNow.Add(BreakerCooldown)) {
		t.Errorf("attempts %d, delivery %+v", r.count()-before, last)
	}
	if s := logs.String(); !strings.Contains(s, "category=http_status") || strings.Contains(s, "secret-part") {
		t.Errorf("logs %s", s)
	}

	// An open circuit skips the webhook.
	tg.CircuitOpenUntil = fixedNow.Add(time.Minute)
	store.set("ten_a", tg)
	before = r.count()
	d.Handle(context.Background(), tenantEvent("ten_a"))
	if d.SkippedOpenCircuit() != 1 || r.count() != before {
		t.Errorf("skipped %d", d.SkippedOpenCircuit())
	}
}

func TestDeliverBreakerState(t *testing.T) {
	r := newReceiver(t)
	tg := genericTarget(r)
	store := &fakeStore{targets: map[string][]Target{}}
	d, _ := newTestDispatcher(t, store, testClient(t, r, nil), nil)
	sem := make(chan struct{}, 1)
	j := job{ctx: context.Background(), tenantID: "ten_a", id: tg.ID, ev: testEvent()}

	// The state read just before the attempt is authoritative: an open
	// circuit skips the delivery, whatever the queue knew when it was
	// queued.
	open := tg
	open.ConsecutiveFailures, open.CircuitOpenUntil = BreakerThreshold, fixedNow.Add(time.Minute)
	store.set("ten_a", open)
	d.deliver(sem, j)
	if d.SkippedOpenCircuit() != 1 || r.count() != 0 {
		t.Fatalf("open circuit not skipped")
	}
	// Re-enabled meanwhile (closed circuit, new version): delivered, and
	// recorded against the new version.
	reenabled := tg
	reenabled.Version = tg.Version.Add(time.Hour)
	store.set("ten_a", reenabled)
	d.deliver(sem, j)
	_, records := store.snapshot()
	if d.Delivered() != 1 || len(records) != 1 || !records[0].d.Version.Equal(reenabled.Version) ||
		records[0].d.ConsecutiveFailures != 0 || !records[0].d.CircuitOpenUntil.IsZero() {
		t.Errorf("records %+v", records)
	}
	// A failed delivery below the threshold keeps the circuit closed; the
	// recording error is logged.
	r.status = func(int) int { return http.StatusTeapot }
	store.recErr = errBoom
	d.deliver(sem, j)
	_, records = store.snapshot()
	last := records[len(records)-1].d
	if last.ConsecutiveFailures != 1 || !last.CircuitOpenUntil.IsZero() || last.Result.HTTPStatus != http.StatusTeapot {
		t.Errorf("delivery %+v", last)
	}
}

func TestDeliverRereadsTheWebhook(t *testing.T) {
	r := newReceiver(t)
	r.status = func(int) int { return http.StatusBadGateway }
	tg := genericTarget(r)
	sem := make(chan struct{}, 1)
	j := job{ctx: context.Background(), tenantID: "ten_a", id: tg.ID, ev: testEvent()}

	// Deleted (or disabled: the store answers alike) after the first
	// attempt: the retry is not sent and nothing is recorded.
	store := &fakeStore{targets: map[string][]Target{"ten_a": {tg}}, onTarget: func(s *fakeStore, n int) {
		if n == 2 {
			s.targets["ten_a"] = nil
		}
	}}
	d, _ := newTestDispatcher(t, store, testClient(t, r, nil), nil)
	d.deliver(sem, j)
	if _, records := store.snapshot(); r.count() != 1 || len(records) != 0 || d.Dropped() != 1 {
		t.Errorf("deleted: requests %d, records %d, dropped %d", r.count(), len(records), d.Dropped())
	}

	// No longer subscribed to the event, or the store answers for another
	// webhook: dropped before any attempt.
	for name, answer := range map[string]func(Target) Target{
		"unsubscribed": func(t Target) Target { t.Events = []events.Type{events.QuotaWarning}; return t },
		"other id":     func(t Target) Target { t.ID = "whk_other"; return t },
		"other tenant": func(t Target) Target { t.TenantID = "ten_b"; return t },
	} {
		store := &fakeStore{targets: map[string][]Target{"ten_a": {tg}}, answer: answer}
		d, _ := newTestDispatcher(t, store, testClient(t, r, nil), nil)
		before := r.count()
		d.deliver(sem, j)
		if r.count() != before || d.Dropped() != 1 {
			t.Errorf("%s: requests %d, dropped %d", name, r.count()-before, d.Dropped())
		}
	}

	// An unreadable webhook drops the delivery with a warning.
	failing := &fakeStore{targets: map[string][]Target{}, targetErr: errBoom}
	d, logs := newTestDispatcher(t, failing, testClient(t, r, nil), nil)
	d.deliver(sem, j)
	if d.Dropped() != 1 || !strings.Contains(logs.String(), "cannot read the webhook") {
		t.Errorf("dropped %d, logs %s", d.Dropped(), logs.String())
	}

	// Re-addressed with a new secret after the first attempt: the retry
	// goes to the new URL, signed with the new secret, and the delivery is
	// recorded against the new version.
	moved := newReceiver(t)
	next := genericTarget(moved)
	next.Secret, next.Version = []byte(strings.Repeat("cd", 32)), tg.Version.Add(time.Minute)
	store = &fakeStore{targets: map[string][]Target{"ten_a": {tg}}, onTarget: func(s *fakeStore, n int) {
		if n == 2 {
			s.targets["ten_a"] = []Target{next}
		}
	}}
	client := testClient(t, r, func(o *ClientOptions) {
		pool := r.tlsConfig().RootCAs
		pool.AddCert(moved.srv.Certificate())
		o.TLSConfig = &tls.Config{RootCAs: pool}
	})
	d, _ = newTestDispatcher(t, store, client, nil)
	before := r.count()
	d.deliver(sem, j)
	_, records := store.snapshot()
	if r.count()-before != 1 || moved.count() != 1 || len(records) != 1 || !records[0].d.Version.Equal(next.Version) {
		t.Fatalf("old %d, new %d, records %+v", r.count()-before, moved.count(), records)
	}
	if err := verifySignature(moved.reqs[0].Header.Get(HeaderSignature), next.Secret, moved.body[0], time.Now()); err != nil {
		t.Errorf("signature: %v", err)
	}
}

func TestDispatcherStoreErrorsAndWarnings(t *testing.T) {
	store := &fakeStore{subErr: errBoom}
	now := fixedNow
	var mu sync.Mutex
	d, logs := newTestDispatcher(t, store, testClient(t, nil, nil), func(o *DispatcherOptions) {
		o.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
	})
	d.Handle(context.Background(), tenantEvent("ten_a"))
	d.Handle(context.Background(), tenantEvent("ten_a"))
	if n := strings.Count(logs.String(), "cannot read the subscribed webhooks"); n != 1 {
		t.Errorf("%d warnings within the interval", n)
	}
	mu.Lock()
	now = now.Add(DefaultWarnInterval)
	mu.Unlock()
	d.Handle(context.Background(), tenantEvent("ten_a"))
	if n := strings.Count(logs.String(), "cannot read the subscribed webhooks"); n != 2 {
		t.Errorf("%d warnings after the interval", n)
	}
}

// blockingReceiver answers once released, or when the request is
// canceled.
func blockingReceiver(t *testing.T) (*receiver, chan struct{}, chan struct{}) {
	t.Helper()
	r := newReceiver(t)
	release := make(chan struct{})
	started := make(chan struct{}, 100)
	r.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Reading the body lets the server notice a closed connection.
		_, _ = io.Copy(io.Discard, req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, req)
		r.mu.Unlock()
		started <- struct{}{}
		select {
		case <-release:
			w.WriteHeader(http.StatusInternalServerError)
		case <-req.Context().Done():
		}
	})
	return r, release, started
}

func TestDispatcherQueueFull(t *testing.T) {
	r, release, started := blockingReceiver(t)
	tg := genericTarget(r)
	store := &fakeStore{targets: map[string][]Target{"ten_a": {tg}}}
	d, logs := newTestDispatcher(t, store, testClient(t, r, nil), func(o *DispatcherOptions) {
		o.QueueSize = 1
		o.Backoff = func(int) time.Duration { return time.Hour }
	})
	d.Handle(context.Background(), tenantEvent("ten_a"))
	<-started // the first delivery is in flight
	for range 3 {
		d.Handle(context.Background(), tenantEvent("ten_a"))
	}
	if d.Dropped() != 2 || !strings.Contains(logs.String(), "queue full") {
		t.Errorf("dropped %d", d.Dropped())
	}
	close(release)
	// The first delivery now waits an hour before its second attempt:
	// Close abandons it and the queued one.
	eventually(t, "first answer", func() bool { return r.count() == 1 })
	time.Sleep(20 * time.Millisecond)
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.Dropped() != 4 || d.Delivered() != 0 || d.Failed() != 0 {
		t.Errorf("dropped %d delivered %d failed %d", d.Dropped(), d.Delivered(), d.Failed())
	}
	// Once closed, nothing is queued.
	d.Handle(context.Background(), tenantEvent("ten_a"))
	if d.Dropped() != 5 {
		t.Errorf("dropped after close %d", d.Dropped())
	}
	if err := d.Close(context.Background()); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func TestDispatcherCloseCancelsInFlight(t *testing.T) {
	r, _, started := blockingReceiver(t)
	a := genericTarget(r)
	b := genericTarget(r)
	b.ID = "whk_2"
	store := &fakeStore{targets: map[string][]Target{"ten_a": {a, b}}}
	d, _ := newTestDispatcher(t, store, testClient(t, r, nil), func(o *DispatcherOptions) { o.TenantParallelism = 1 })
	d.Handle(context.Background(), tenantEvent("ten_a"))
	<-started // one webhook in flight, the other waits for the tenant slot
	time.Sleep(20 * time.Millisecond)
	if r.count() != 1 {
		t.Fatalf("parallelism not limited: %d requests", r.count())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := d.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close: %v", err)
	}
	if d.Dropped() != 2 || d.Failed() != 0 {
		t.Errorf("dropped %d failed %d", d.Dropped(), d.Failed())
	}
	if _, records := store.snapshot(); len(records) != 0 {
		t.Errorf("abandoned deliveries recorded: %+v", records)
	}
}

func TestDispatcherCloseAbandonsQueue(t *testing.T) {
	r, release, started := blockingReceiver(t)
	tg := genericTarget(r)
	store := &fakeStore{targets: map[string][]Target{"ten_a": {tg}}}
	d, _ := newTestDispatcher(t, store, testClient(t, r, nil), nil)
	d.Handle(context.Background(), tenantEvent("ten_a"))
	<-started
	d.Handle(context.Background(), tenantEvent("ten_a"))
	d.Handle(context.Background(), tenantEvent("ten_a"))
	done := make(chan error)
	go func() { done <- d.Close(context.Background()) }()
	// The in-flight attempt may end; its failure is abandoned with the
	// queue.
	time.Sleep(20 * time.Millisecond)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d.Dropped() != 3 || r.count() != 1 {
		t.Errorf("dropped %d, requests %d", d.Dropped(), r.count())
	}
}

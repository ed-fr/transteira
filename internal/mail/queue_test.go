package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// funcSender adapts a function to Sender.
type funcSender func(ctx context.Context, s Settings, m Message) error

func (f funcSender) Send(ctx context.Context, s Settings, m Message) error { return f(ctx, s, m) }

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

// testLogger returns a debug-level logger writing into a buffer.
func testLogger() (*slog.Logger, *syncBuffer) {
	b := &syncBuffer{}
	return slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})), b
}

// testJob returns a valid job.
func testJob() Job {
	return Job{TenantID: "ten_a", Template: TemplateVerificationCode, Settings: buildSettings(), Message: Message{
		To: []string{"Bob@Example.com"}, Subject: "Your code", Text: "code 654321",
	}}
}

func TestQueueDelivers(t *testing.T) {
	var sent atomic.Int32
	done := make(chan struct{}, 10)
	q := NewQueue(funcSender(func(_ context.Context, _ Settings, m Message) error {
		if m.Text != "code 654321" {
			t.Errorf("message %+v", m)
		}
		sent.Add(1)
		done <- struct{}{}
		return nil
	}), 10, nil, QueueOptions{Workers: 2, TenantConcurrency: 2, TenantQueued: 10})
	for range 5 {
		if err := q.Enqueue(testJob()); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 5 {
		t.Fatalf("sent %d", sent.Load())
	}
	if err := q.Enqueue(testJob()); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("after close: %v", err)
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestQueueRetry(t *testing.T) {
	logger, logs := testLogger()
	var calls atomic.Int32
	q := NewQueue(funcSender(func(context.Context, Settings, Message) error {
		if calls.Add(1) == 1 {
			return errors.New("temporary")
		}
		return nil
	}), 1, logger, QueueOptions{RetryDelay: time.Millisecond})
	if err := q.Enqueue(testJob()); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls %d", calls.Load())
	}
	if !strings.Contains(logs.String(), "mail sent") || !strings.Contains(logs.String(), "attempt=2") {
		t.Fatalf("logs: %s", logs.String())
	}
}

func TestQueueFailureLog(t *testing.T) {
	logger, logs := testLogger()
	var calls atomic.Int32
	q := NewQueue(funcSender(func(_ context.Context, _ Settings, _ Message) error {
		calls.Add(1)
		return errors.New("550 5.1.1 <BOB@example.com>: recipient rejected; also bob@example.com")
	}), 1, logger, QueueOptions{RetryDelay: time.Millisecond})
	if err := q.Enqueue(testJob()); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != maxAttempts {
		t.Fatalf("calls %d", calls.Load())
	}
	out := logs.String()
	for _, leak := range []string{"bob@example.com", "BOB@example.com", "Bob@Example.com", "654321", "Your code"} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaks %q: %s", leak, out)
		}
	}
	h := AddressHash("bob@example.com")
	for _, want := range []string{"mail delivery failed", "tenant=ten_a", "template=verification_code", h, "[addr:" + h + "]", "recipient rejected"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q: %s", want, out)
		}
	}
}

func TestQueueFull(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 10)
	q := NewQueue(funcSender(func(context.Context, Settings, Message) error {
		started <- struct{}{}
		<-release
		return nil
	}), 1, nil, QueueOptions{})
	if err := q.Enqueue(testJob()); err != nil {
		t.Fatal(err)
	}
	<-started // the worker holds job 1
	if err := q.Enqueue(testJob()); err != nil {
		t.Fatal(err) // job 2 fills the buffer
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d", q.Len())
	}
	if err := q.Enqueue(testJob()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want ErrQueueFull, got %v", err)
	}
	close(release)
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestQueueEnqueueValidates(t *testing.T) {
	q := NewQueue(funcSender(func(context.Context, Settings, Message) error { return nil }), 0, nil, QueueOptions{})
	defer func() { _ = q.Close(context.Background()) }()
	want := QueueOptions{
		Workers: DefaultWorkers, TenantConcurrency: DefaultTenantConcurrency, TenantQueued: DefaultQueueSize / 4,
		RetryDelay: DefaultRetryDelay, BreakerThreshold: DefaultBreakerThreshold, BreakerCooldown: DefaultBreakerCooldown,
	}
	if q.size != DefaultQueueSize || q.opts != want {
		t.Fatalf("defaults: %d %+v", q.size, q.opts)
	}
	j := testJob()
	j.Settings.Host = ""
	if err := q.Enqueue(j); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("settings: %v", err)
	}
	j = testJob()
	j.Message.Subject = "a\r\nBcc: eve@example.com"
	if err := q.Enqueue(j); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("message: %v", err)
	}
}

func TestQueueCloseTimeout(t *testing.T) {
	logger, logs := testLogger()
	started := make(chan struct{}, 10)
	q := NewQueue(funcSender(func(ctx context.Context, _ Settings, _ Message) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}), 10, logger, QueueOptions{RetryDelay: time.Hour, TenantQueued: 10})
	for range 3 {
		if err := q.Enqueue(testJob()); err != nil {
			t.Fatal(err)
		}
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := q.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close: %v", err)
	}
	out := logs.String()
	if strings.Count(out, "mail dropped at shutdown") != 2 || strings.Count(out, "mail delivery failed") != 1 {
		t.Fatalf("logs: %s", out)
	}
	if n := q.Dropped(); n != 2 {
		t.Errorf("Dropped = %d, want 2", n)
	}
}

func TestQueueRetryInterruptedByClose(t *testing.T) {
	logger, logs := testLogger()
	failed := make(chan struct{}, 1)
	q := NewQueue(funcSender(func(context.Context, Settings, Message) error {
		failed <- struct{}{}
		return errors.New("down")
	}), 1, logger, QueueOptions{RetryDelay: time.Hour})
	if err := q.Enqueue(testJob()); err != nil {
		t.Fatal(err)
	}
	<-failed // first attempt done, worker now waits for the retry
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := q.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("retry back-off not interrupted")
	}
	if !strings.Contains(logs.String(), "context canceled") {
		t.Fatalf("logs: %s", logs.String())
	}
}

func TestAddressHashAndRedaction(t *testing.T) {
	if AddressHash(" Bob@Example.com ") != AddressHash("bob@example.com") || len(AddressHash("x")) != 16 {
		t.Fatal("AddressHash must be case-insensitive and 16 hex digits")
	}
	plain := sha256.Sum256([]byte("bob@example.com"))
	if AddressHash("bob@example.com") == hex.EncodeToString(plain[:8]) {
		t.Fatal("AddressHash must be keyed, not a plain SHA-256")
	}
	if len(addressHashKey) != 32 || bytes.Equal(addressHashKey, make([]byte, 32)) || bytes.Equal(newAddressHashKey(), addressHashKey) {
		t.Fatal("the AddressHash key must be 32 random bytes")
	}
	if AddressHash("a@example.com") == AddressHash("b@example.com") {
		t.Fatal("collision")
	}
	got := redactAddresses("x BOB@example.com y bob@example.com", []string{"", "bob@example.com"})
	if strings.Contains(strings.ToLower(got), "bob@example.com") || strings.Count(got, "[addr:") != 2 {
		t.Fatalf("redact: %q", got)
	}
	// A case mapping that changes byte lengths falls back to exact matching.
	if got := replaceFold("İ bob@example.com", "bob@example.com", "X"); got != "İ X" {
		t.Fatalf("fallback: %q", got)
	}
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// tenantJob returns a valid job of the given tenant.
func tenantJob(tenant string) Job {
	j := testJob()
	j.TenantID = tenant
	return j
}

func TestQueueFairness(t *testing.T) {
	release := make(chan struct{})
	var bStarted, aSent atomic.Int32
	q := NewQueue(funcSender(func(ctx context.Context, s Settings, _ Message) error {
		if s.Host == "smtp.b.example.com" {
			bStarted.Add(1)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		}
		aSent.Add(1)
		return nil
	}), 100, nil, QueueOptions{Workers: 4, TenantConcurrency: 1, TenantQueued: 2})
	jobB := tenantJob("ten_b")
	jobB.Settings.Host = "smtp.b.example.com"

	if err := q.Enqueue(jobB); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first B delivery", func() bool { return bStarted.Load() == 1 })
	for range 2 {
		if err := q.Enqueue(jobB); err != nil {
			t.Fatal(err)
		}
	}
	// B has 2 waiting jobs: its share is full, and only B is refused.
	if err := q.Enqueue(jobB); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("B over its share: %v", err)
	}
	for round := 1; round <= 3; round++ {
		for range 2 {
			if err := q.Enqueue(tenantJob("ten_a")); err != nil {
				t.Fatalf("A refused while B is stuck: %v", err)
			}
		}
		want := int32(2 * round)
		waitFor(t, "A deliveries", func() bool { return aSent.Load() == want })
	}
	// B never had more than one delivery in flight.
	if n := bStarted.Load(); n != 1 {
		t.Fatalf("B deliveries in flight: %d", n)
	}
	if q.Len() != 2 {
		t.Fatalf("Len = %d", q.Len())
	}
	close(release)
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bStarted.Load() != 3 || aSent.Load() != 6 {
		t.Fatalf("delivered B=%d A=%d", bStarted.Load(), aSent.Load())
	}
}

func TestQueueGlobalCapacity(t *testing.T) {
	release := make(chan struct{})
	q := NewQueue(funcSender(func(context.Context, Settings, Message) error {
		<-release
		return nil
	}), 2, nil, QueueOptions{Workers: 1, TenantQueued: 5})
	// One job may be taken by the worker; keep enqueuing distinct tenants
	// until the global capacity refuses one.
	var err error
	for i := 0; i < 10 && err == nil; i++ {
		err = q.Enqueue(tenantJob(fmt.Sprintf("ten_%d", i)))
	}
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("global capacity: %v", err)
	}
	close(release)
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestQueueCircuitBreaker(t *testing.T) {
	logger, logs := testLogger()
	var (
		mu      sync.Mutex
		now     = time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
		failing = true
	)
	// Every attempt for tenant B waits for a token: the test drives them one
	// by one.
	token := make(chan struct{})
	var calls atomic.Int32
	q := NewQueue(funcSender(func(_ context.Context, s Settings, _ Message) error {
		if s.Host != "smtp.b.example.com" {
			return nil
		}
		<-token
		calls.Add(1)
		mu.Lock()
		defer mu.Unlock()
		if failing {
			return fmt.Errorf("%w: connect: connection refused", ErrSMTP)
		}
		return nil
	}), 100, logger, QueueOptions{
		Workers: 2, TenantQueued: 10, RetryDelay: time.Millisecond,
		BreakerThreshold: 3, BreakerCooldown: time.Minute,
	})
	q.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
	jobB := tenantJob("ten_b")
	jobB.Settings.Host = "smtp.b.example.com"
	wantOpenRefusal := func(when string) {
		t.Helper()
		if err := q.Enqueue(jobB); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("%s: Enqueue = %v, want ErrCircuitOpen", when, err)
		}
	}

	// Job 1 fails twice, job 2 fails once and opens the circuit (no retry);
	// job 3, still queued, is dropped at once and counted.
	for range 3 {
		if err := q.Enqueue(jobB); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		token <- struct{}{}
	}
	waitFor(t, "circuit open", func() bool { return q.circuitOpen("ten_b") })
	wantOpenRefusal("open")
	waitFor(t, "two failures logged", func() bool { return strings.Count(logs.String(), "mail delivery failed") == 2 })
	if q.Len() != 0 || calls.Load() != 3 {
		t.Fatalf("Len=%d attempts=%d", q.Len(), calls.Load())
	}
	if !strings.Contains(logs.String(), "dropped=1") {
		t.Fatalf("dropped job not counted: %s", logs.String())
	}
	if n := q.Dropped(); n != 1 {
		t.Errorf("Dropped = %d, want 1", n)
	}
	// Other tenants are unaffected.
	if err := q.Enqueue(tenantJob("ten_a")); err != nil {
		t.Fatalf("A: %v", err)
	}

	// Half-open: exactly one probe is accepted; it fails and reopens the
	// circuit without a second warning.
	advance(time.Minute + time.Second)
	if err := q.Enqueue(jobB); err != nil {
		t.Fatalf("probe: %v", err)
	}
	wantOpenRefusal("probe pending")
	token <- struct{}{}
	waitFor(t, "circuit reopened", func() bool { return calls.Load() == 4 && q.circuitOpen("ten_b") })
	wantOpenRefusal("reopened")

	// Next half-open: the server is back, the probe closes the circuit.
	advance(time.Minute + time.Second)
	mu.Lock()
	failing = false
	mu.Unlock()
	if err := q.Enqueue(jobB); err != nil {
		t.Fatalf("second probe: %v", err)
	}
	wantOpenRefusal("second probe pending")
	token <- struct{}{}
	waitFor(t, "circuit closed", func() bool { return strings.Contains(logs.String(), "mail circuit closed") })
	for range 2 {
		if err := q.Enqueue(jobB); err != nil {
			t.Fatalf("after close: %v", err)
		}
	}
	token <- struct{}{}
	token <- struct{}{}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if n := strings.Count(out, "mail circuit open"); n != 1 {
		t.Fatalf("%d circuit-open warnings:\n%s", n, out)
	}
	if strings.Count(out, "mail delivery failed") != 3 || !strings.Contains(out, "tenant=ten_b") || strings.Contains(out, "bob@example.com") {
		t.Fatalf("logs: %s", out)
	}
}

func TestQueuePurgeClearsSlots(t *testing.T) {
	q := &Queue{tenants: map[string]*tenantState{}}
	ts := &tenantState{}
	q.tenants["a"], q.tenants["b"] = ts, &tenantState{jobs: []Job{testJob()}}
	j := testJob()
	j.Settings.Password = "pw-marker-99"
	ts.jobs = []Job{j, j}
	backing := ts.jobs
	q.order, q.total = []string{"b", "a"}, 3
	if n := q.purge("a", ts); n != 2 || q.total != 1 || len(q.order) != 1 || q.order[0] != "b" {
		t.Fatalf("purge: n=%d total=%d order=%v", n, q.total, q.order)
	}
	for _, b := range backing {
		if b.Settings.Password != "" {
			t.Fatal("purged slot still holds the password")
		}
	}
	if q.purge("a", ts) != 0 {
		t.Fatal("second purge")
	}
}

func TestQueueNextClearsSlot(t *testing.T) {
	q := NewQueue(funcSender(func(context.Context, Settings, Message) error { return nil }), 10, nil, QueueOptions{Workers: 1})
	_ = q.Close(context.Background()) // stop the worker; next is driven by hand
	j := testJob()
	j.Settings.Password = "pw-marker-99"
	ts := &tenantState{jobs: []Job{j, j}}
	backing := ts.jobs
	q.tenants["ten_a"], q.order, q.total = ts, []string{"ten_a"}, 2
	if got, ok := q.next(); !ok || got.Settings.Password != "pw-marker-99" {
		t.Fatalf("next: %v", ok)
	}
	if backing[0].Settings.Password != "" {
		t.Fatal("dequeued slot still holds the password")
	}
}

func TestCountsAsFailure(t *testing.T) {
	cases := map[error]bool{
		fmt.Errorf("%w: connect: refused", ErrSMTP):             true,
		fmt.Errorf("%w: %w", context.DeadlineExceeded, ErrSMTP): true,
		ErrAuthFailed: true,
		fmt.Errorf("%w: RCPT TO: %w", ErrSMTP, &textproto.Error{Code: 550, Msg: "no"}): false,
		fmt.Errorf("%w: %w", context.Canceled, ErrSMTP):                                false,
	}
	for err, want := range cases {
		if got := countsAsFailure(err); got != want {
			t.Errorf("countsAsFailure(%v) = %v", err, got)
		}
	}
}

func TestQueueRejectionDoesNotTrip(t *testing.T) {
	q := NewQueue(funcSender(func(context.Context, Settings, Message) error {
		return fmt.Errorf("%w: RCPT TO: %w", ErrSMTP, &textproto.Error{Code: 550, Msg: "unknown user"})
	}), 10, nil, QueueOptions{Workers: 1, TenantQueued: 10, RetryDelay: time.Millisecond, BreakerThreshold: 1})
	for range 3 {
		if err := q.Enqueue(testJob()); err != nil {
			t.Fatalf("a reachable server rejecting must not open the circuit: %v", err)
		}
		waitFor(t, "drain", func() bool { return q.Len() == 0 })
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

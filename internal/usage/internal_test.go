package usage

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

var (
	testDay = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	errDown = errors.New("database down")
)

// fakeAdder records the counters added, failing as configured.
type fakeAdder struct {
	mu      sync.Mutex
	fail    map[tenant.ID]error // per tenant
	all     error               // every call
	block   chan struct{}       // blocks the calls until closed (or ctx done)
	blockN  int                 // with block: only the first blockN calls block (0: all)
	deaf    bool                // with block: ignore ctx while blocked
	entered chan struct{}       // when set, receives a value as each call starts
	added   map[key]store.UsageCounts
	calls   int
}

func newFake() *fakeAdder {
	return &fakeAdder{fail: map[tenant.ID]error{}, added: map[key]store.UsageCounts{}}
}

func (f *fakeAdder) Add(ctx context.Context, tid tenant.ID, day time.Time, c store.UsageCounts) error {
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	f.mu.Lock()
	f.calls++
	block := f.block != nil && (f.blockN == 0 || f.calls <= f.blockN)
	f.mu.Unlock()
	switch {
	case block && f.deaf:
		<-f.block
	case block:
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.all != nil {
		return f.all
	}
	if err := f.fail[tid]; err != nil {
		return err
	}
	k := key{tid: tid, day: day.Unix()}
	f.added[k] = sum(f.added[k], c)
	return nil
}

func (f *fakeAdder) get(tid tenant.ID, day time.Time) store.UsageCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.added[key{tid: tid, day: day.Unix()}]
}

// logBuffer is a concurrency-safe log destination.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newLogged(f *fakeAdder, opts Options) (*Recorder, *logBuffer) {
	var logs logBuffer
	opts.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return newRecorder(f, opts), &logs
}

func TestDefaults(t *testing.T) {
	r := newRecorder(newFake(), Options{})
	if r.interval != DefaultInterval || r.maxPending != DefaultMaxPending || r.now == nil || r.logger == nil {
		t.Errorf("defaults = %+v", r)
	}
}

func TestFailedFlushRetry(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r, logs := newLogged(f, Options{})
	f.fail["tnt_b"] = errDown
	f.fail["tnt_bad"] = store.ErrInvalid

	r.TransferFinalized("tnt_a", 10, testDay)
	r.TransferFinalized("tnt_b", 20, testDay)
	r.TransferFinalized("tnt_bad", 30, testDay)
	err := r.Flush(ctx)
	if !errors.Is(err, errDown) || !strings.Contains(err.Error(), "1 of 3") {
		t.Fatalf("Flush = %v, want the failure of tenant B", err)
	}
	if got := f.get("tnt_a", testDay); got.BytesUploaded != 10 {
		t.Errorf("tenant A = %+v, want flushed despite B", got)
	}
	if r.Pending() != 1 {
		t.Fatalf("Pending = %d, want tenant B kept", r.Pending())
	}
	if !strings.Contains(logs.String(), "unknown tenant dropped") {
		t.Errorf("logs = %s, want the invalid tenant dropped", logs)
	}

	// Recorded meanwhile, merged with the kept counters, then flushed.
	r.TransferFinalized("tnt_b", 5, testDay)
	delete(f.fail, "tnt_b")
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("retry Flush = %v", err)
	}
	if got := f.get("tnt_b", testDay); got != (store.UsageCounts{Transfers: 2, BytesUploaded: 25}) {
		t.Errorf("tenant B = %+v, want the kept and new counters once", got)
	}
	if r.Pending() != 0 {
		t.Errorf("Pending = %d", r.Pending())
	}
}

func TestPendingBound(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r, logs := newLogged(f, Options{MaxPending: 2})

	// Recording beyond the bound drops the oldest day.
	r.DownloadStarted("tnt_b", testDay.Add(-48*time.Hour))
	r.DownloadStarted("tnt_a", testDay.Add(-48*time.Hour)) // same day: tenant order decides
	r.DownloadStarted("tnt_a", testDay)
	if r.Pending() != 2 {
		t.Fatalf("Pending = %d, want 2", r.Pending())
	}
	if !strings.Contains(logs.String(), "bound reached") || !strings.Contains(logs.String(), "tenant=tnt_a") {
		t.Errorf("logs = %s, want the oldest entry (tenant A, 2 days ago) dropped", logs)
	}
	r.DownloadStarted("tnt_a", testDay) // existing entry: nothing dropped
	if r.Pending() != 2 {
		t.Fatalf("Pending = %d, want 2", r.Pending())
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("Flush = %v", err)
	}
	if got := f.get("tnt_a", testDay); got.Downloads != 2 {
		t.Errorf("tenant A = %+v", got)
	}
	if got := f.get("tnt_b", testDay.Add(-48*time.Hour)); got.Downloads != 1 {
		t.Errorf("tenant B = %+v", got)
	}
}

// overflowAdder fails every call, recording new entries into r during the
// flush so that the merge-back overflows the bound.
type overflowAdder struct {
	r    *Recorder
	once sync.Once
}

func (o *overflowAdder) Add(context.Context, tenant.ID, time.Time, store.UsageCounts) error {
	o.once.Do(func() {
		o.r.TransferFinalized("tnt_x", 1, testDay.Add(24*time.Hour))
		o.r.TransferFinalized("tnt_y", 1, testDay.Add(24*time.Hour))
	})
	return errDown
}

func TestMergeBackOverflow(t *testing.T) {
	o := &overflowAdder{}
	var logs logBuffer
	r := newRecorder(o, Options{MaxPending: 2, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	o.r = r
	r.TransferFinalized("tnt_old", 1, testDay)
	if err := r.Flush(context.Background()); !errors.Is(err, errDown) {
		t.Fatalf("Flush = %v", err)
	}
	if r.Pending() != 2 {
		t.Fatalf("Pending = %d, want 2", r.Pending())
	}
	// The kept entry (oldest day) is the one dropped.
	if !strings.Contains(logs.String(), "tenant=tnt_old") {
		t.Errorf("logs = %s, want tnt_old dropped", logs.String())
	}
	r.mu.Lock()
	_, kept := r.pending[key{tid: "tnt_old", day: testDay.Unix()}]
	r.mu.Unlock()
	if kept {
		t.Error("tnt_old still pending")
	}
}

func (f *fakeAdder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestRunFlushFailureLogged(t *testing.T) {
	f := newFake()
	f.all = errDown
	f.entered = make(chan struct{}, 1)
	r, logs := newLogged(f, Options{Interval: time.Millisecond})
	r.VirusDetected("tnt_a", testDay)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "flush failed") {
		if time.Now().After(deadline) {
			t.Fatal("the failed periodic flush was not logged")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if r.Pending() != 1 {
		t.Errorf("Pending = %d, want the counters kept", r.Pending())
	}
}

func TestRunCanceledFlushNotLogged(t *testing.T) {
	f := newFake()
	f.block = make(chan struct{})
	defer close(f.block)
	f.entered = make(chan struct{}, 1)
	r, logs := newLogged(f, Options{Interval: time.Millisecond})
	r.VirusDetected("tnt_a", testDay)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	<-f.entered
	cancel()
	<-done
	if strings.Contains(logs.String(), "flush failed") {
		t.Errorf("logs = %s, want no error for a flush canceled by the stop", logs)
	}
	if r.Pending() != 1 {
		t.Errorf("Pending = %d, want the counters kept for the final flush", r.Pending())
	}
}

// TestShutdownCounts checks that the counters recorded after the start
// context is canceled (the shutdown signal) and before Close reach the
// final flush of Close, and that nothing is written after Close.
func TestShutdownCounts(t *testing.T) {
	f := newFake()
	r := newRecorder(f, Options{Interval: time.Millisecond})
	sig, stop := context.WithCancel(context.Background())
	if err := r.Start(sig); err != nil {
		t.Fatalf("Start = %v", err)
	}
	stop()
	r.BytesServed("tnt_a", 7, testDay)
	r.VirusDetected("tnt_a", testDay)
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if got := f.get("tnt_a", testDay); got != (store.UsageCounts{BytesDownloaded: 7, VirusDetections: 1}) {
		t.Errorf("flushed = %+v, want the counters recorded after the signal", got)
	}
	calls := f.callCount()
	r.TransferFinalized("tnt_a", 1, testDay)
	time.Sleep(20 * time.Millisecond)
	if f.callCount() != calls {
		t.Error("the recorder wrote after Close")
	}
	if r.Pending() != 1 {
		t.Errorf("Pending = %d, want the late counters kept in memory", r.Pending())
	}
}

// TestCloseCancelsPeriodicFlush checks that Close interrupts a periodic
// flush in progress and makes the final flush itself, with its own
// context.
func TestCloseCancelsPeriodicFlush(t *testing.T) {
	f := newFake()
	f.block = make(chan struct{})
	defer close(f.block)
	f.blockN = 1
	f.entered = make(chan struct{}, 1)
	r := newRecorder(f, Options{Interval: time.Millisecond})
	r.DownloadStarted("tnt_a", testDay)
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start = %v", err)
	}
	<-f.entered // the periodic flush is blocked
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if got := f.get("tnt_a", testDay); got.Downloads != 1 {
		t.Errorf("flushed = %+v, want the counters of the canceled flush", got)
	}
}

func TestCloseTimeout(t *testing.T) {
	f := newFake()
	f.block = make(chan struct{})
	defer close(f.block)
	r := newRecorder(f, Options{Interval: time.Hour})
	r.DownloadStarted("tnt_a", testDay)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close = %v, want DeadlineExceeded while the final flush hangs", err)
	}
}

func TestCloseTimeoutWhileRunHangs(t *testing.T) {
	f := newFake()
	f.block = make(chan struct{})
	f.deaf = true
	f.entered = make(chan struct{}, 1)
	defer close(f.block)
	r := newRecorder(f, Options{Interval: time.Millisecond})
	r.DownloadStarted("tnt_a", testDay)
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start = %v", err)
	}
	<-f.entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close = %v, want DeadlineExceeded while Run hangs", err)
	}
}

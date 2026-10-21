package mail

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptQueue returns errs in order, then nil, and records the accepted
// jobs; block, when set, makes the next Enqueue wait on it.
type scriptQueue struct {
	mu      sync.Mutex
	errs    []error
	jobs    []Job
	block   chan struct{}
	entered chan struct{}
}

func (q *scriptQueue) Enqueue(j Job) error {
	q.mu.Lock()
	block, entered := q.block, q.entered
	q.block, q.entered = nil, nil
	q.mu.Unlock()
	if block != nil {
		close(entered)
		<-block
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.errs) > 0 {
		err := q.errs[0]
		q.errs = q.errs[1:]
		if err != nil {
			return err
		}
	}
	q.jobs = append(q.jobs, j)
	return nil
}

func (q *scriptQueue) accepted() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}

// count returns the occurrences of msg in the logs.
func (b *syncBuffer) count(msg string) int { return strings.Count(b.String(), msg) }

func newTestRetrier(q *scriptQueue, opts RetryOptions) (*Retrier, *syncBuffer) {
	logs := &syncBuffer{}
	opts.Logger = slog.New(slog.NewTextHandler(logs, nil))
	if opts.Min == 0 {
		opts.Min, opts.Max = time.Millisecond, 4*time.Millisecond
	}
	return NewRetrier(q, opts), logs
}

func TestRetrierRetries(t *testing.T) {
	q := &scriptQueue{errs: []error{ErrQueueFull, ErrQueueClosed, ErrCircuitOpen, ErrQueueFull, nil}}
	r, logs := newTestRetrier(q, RetryOptions{})
	r.Send(context.Background(), []Job{{Template: "a"}, {Template: "b"}, {Template: "c"}}, slog.String("transfer", "trf_1"))
	waitFor(t, "jobs", func() bool { return q.accepted() == 2 && r.Pending() == 0 })
	if logs.count("will retry") != 2 || logs.count(`msg="notification mail refused"`) != 1 {
		t.Fatalf("logs:\n%s", logs.String())
	}
	if logs.count("transfer=trf_1") == 0 {
		t.Fatal("attributes not logged")
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRetrierGivesUp(t *testing.T) {
	q := &scriptQueue{errs: []error{ErrQueueFull, ErrQueueFull, ErrQueueFull, ErrQueueFull}}
	r, logs := newTestRetrier(q, RetryOptions{For: 4 * time.Millisecond})
	r.Send(context.Background(), []Job{{}})
	waitFor(t, "drop", func() bool { return logs.count("kept refusing") == 1 })
	if q.accepted() != 0 {
		t.Fatal("job accepted")
	}
}

func TestRetrierClose(t *testing.T) {
	q := &scriptQueue{errs: []error{ErrQueueFull}}
	r, logs := newTestRetrier(q, RetryOptions{Min: time.Hour, Max: time.Hour, For: 2 * time.Hour})
	r.Send(context.Background(), []Job{{}, {}})
	if r.Pending() != 1 || q.accepted() != 1 {
		t.Fatalf("pending %d, accepted %d", r.Pending(), q.accepted())
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	q.errs = []error{ErrCircuitOpen}
	r.Send(context.Background(), []Job{{}})
	if logs.count("dropped at shutdown") != 2 || r.Pending() != 0 {
		t.Fatalf("logs:\n%s", logs.String())
	}
}

func TestRetrierCloseWaits(t *testing.T) {
	q := &scriptQueue{errs: []error{ErrQueueFull}}
	r, _ := newTestRetrier(q, RetryOptions{Min: 50 * time.Millisecond, Max: 50 * time.Millisecond})
	r.Send(context.Background(), []Job{{}})
	release := make(chan struct{})
	q.mu.Lock()
	q.block, q.entered = release, make(chan struct{})
	entered := q.entered
	q.mu.Unlock()
	<-entered // the retry is in progress
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close = %v", err)
	}
	close(release)
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBackoffAndDefaults(t *testing.T) {
	for n, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 5 * time.Second, 40: 5 * time.Second} {
		if got := Backoff(time.Second, 5*time.Second, n); got != want {
			t.Errorf("Backoff(%d) = %s, want %s", n, got, want)
		}
	}
	r := NewRetrier(&scriptQueue{}, RetryOptions{})
	if r.opts.For != DefaultRetryFor || r.opts.Min != DefaultRetryMin || r.opts.Max != DefaultRetryMax || r.opts.Now == nil || r.opts.Logger == nil {
		t.Fatalf("defaults %+v", r.opts)
	}
	if r := NewRetrier(&scriptQueue{}, RetryOptions{Min: time.Hour}); r.opts.Max != time.Hour {
		t.Fatalf("Max %s", r.opts.Max)
	}
}

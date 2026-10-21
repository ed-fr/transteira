package mail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Defaults of [RetryOptions].
const (
	// DefaultRetryFor is how long refused mails are retried.
	DefaultRetryFor = time.Hour
	// DefaultRetryMin is the first retry delay.
	DefaultRetryMin = 30 * time.Second
	// DefaultRetryMax is the longest retry delay.
	DefaultRetryMax = 10 * time.Minute
)

// Enqueuer queues mails without blocking. *Queue implements it.
type Enqueuer interface {
	Enqueue(job Job) error
}

// RetryOptions tunes a [Retrier]. Zero values select the defaults.
type RetryOptions struct {
	// For is how long the mails of one Send are retried (DefaultRetryFor
	// when <= 0).
	For time.Duration
	// Min is the first retry delay (DefaultRetryMin when <= 0).
	Min time.Duration
	// Max is the longest retry delay (DefaultRetryMax when below Min:
	// the larger of DefaultRetryMax and Min).
	Max time.Duration
	// Now is the clock of the deadlines (time.Now when nil).
	Now func() time.Time
	// Logger receives one line per refusal, retry and drop, with the
	// attributes given to Send and never an address (nil discards).
	Logger *slog.Logger
}

// Retrier enqueues mails on an [Enqueuer] and retries those it refuses
// because the queue is full ([ErrQueueFull]) or the tenant's circuit is
// open ([ErrCircuitOpen]): the refused mails are enqueued again after a
// delay that starts at RetryOptions.Min and doubles up to
// RetryOptions.Max, until RetryOptions.For after the Send, then dropped
// with an error line. Any other refusal drops the mail with an error line.
// It is shared by the components that notify (antivirus worker, download
// service) and is safe for concurrent use. Close it with [Retrier.Close].
type Retrier struct {
	q      Enqueuer
	opts   RetryOptions
	mu     sync.Mutex
	closed bool
	timers map[*time.Timer]batch
	wg     sync.WaitGroup
}

// batch is a set of refused mails waiting for a retry.
type batch struct {
	ctx      context.Context //nolint:containedctx // detached context of the Send, for the logs of the retries
	jobs     []Job
	attrs    []slog.Attr
	deadline time.Time
	attempt  int
}

// NewRetrier returns a retrier over q.
func NewRetrier(q Enqueuer, opts RetryOptions) *Retrier {
	if opts.For <= 0 {
		opts.For = DefaultRetryFor
	}
	if opts.Min <= 0 {
		opts.Min = DefaultRetryMin
	}
	if opts.Max < opts.Min {
		opts.Max = max(DefaultRetryMax, opts.Min)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Retrier{q: q, opts: opts, timers: map[*time.Timer]batch{}}
}

// Backoff returns the n-th retry delay (n >= 1): min doubled n-1 times, at
// most max.
func Backoff(minDelay, maxDelay time.Duration, n int) time.Duration {
	d := minDelay
	for i := 1; i < n && d < maxDelay; i++ {
		d *= 2
	}
	return min(d, maxDelay)
}

// Send enqueues jobs without blocking, retrying the refused ones as the
// type documentation describes. attrs identify the jobs in the logs (for
// example the tenant and transfer IDs); they must never hold an address.
// After Close, refused mails are dropped at once.
func (r *Retrier) Send(ctx context.Context, jobs []Job, attrs ...slog.Attr) {
	r.send(batch{ctx: context.WithoutCancel(ctx), jobs: jobs, attrs: attrs, deadline: r.opts.Now().Add(r.opts.For)})
}

// send enqueues the jobs of b and schedules a retry of the refused ones.
func (r *Retrier) send(b batch) {
	var refused []Job
	for _, j := range b.jobs {
		err := r.q.Enqueue(j)
		switch {
		case err == nil:
		case errors.Is(err, ErrQueueFull), errors.Is(err, ErrCircuitOpen):
			refused = append(refused, j)
		default:
			r.log(b, slog.LevelError, "notification mail refused",
				slog.String("template", j.Template), slog.Any("error", err))
		}
	}
	if len(refused) == 0 {
		return
	}
	b.jobs = refused
	b.attempt++
	delay := Backoff(r.opts.Min, r.opts.Max, b.attempt)
	if r.opts.Now().Add(delay).After(b.deadline) {
		r.log(b, slog.LevelError, "notification mails dropped: the mail queue kept refusing them", slog.Int("count", len(refused)))
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		r.logDropped(b)
		return
	}
	r.log(b, slog.LevelWarn, "notification mails refused by the queue, will retry",
		slog.Int("count", len(refused)), slog.Duration("retry_in", delay))
	r.wg.Add(1)
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		defer r.wg.Done()
		r.mu.Lock()
		_, ok := r.timers[timer]
		delete(r.timers, timer)
		r.mu.Unlock()
		if ok {
			r.send(b)
		}
	})
	r.timers[timer] = b
}

// Pending returns the number of batches waiting for a retry.
func (r *Retrier) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.timers)
}

// Close drops the mails waiting for a retry, with an error line per
// batch, and waits for a retry in progress to end, at most until ctx is
// done. Calling it more than once is harmless.
func (r *Retrier) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	for timer, b := range r.timers {
		if timer.Stop() {
			r.wg.Done()
		}
		r.logDropped(b)
	}
	clear(r.timers)
	r.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("mail: close retrier: %w", ctx.Err())
	}
}

// logDropped logs the mails of b lost because the retrier is closed.
func (r *Retrier) logDropped(b batch) {
	r.log(b, slog.LevelError, "notification mails dropped at shutdown", slog.Int("count", len(b.jobs)))
}

// log writes a line about b.
func (r *Retrier) log(b batch, level slog.Level, msg string, attrs ...slog.Attr) {
	r.opts.Logger.LogAttrs(b.ctx, level, msg, append(append([]slog.Attr{}, b.attrs...), attrs...)...)
}
